use std::collections::HashMap;

#[cfg(feature = "ldap")]
use ldap3::{Ldap, LdapConnAsync, Scope, SearchEntry};
#[cfg(feature = "ldap")]
use ldap3::result::Result;
use log::{info, trace, warn};
use log::debug;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReadWriteDefinition {
    pub read: Vec<String>,
    pub write: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg(feature = "ldap")]
pub struct LdapConfig {
    pub ldap_url: String,
    pub base_dn: String,
    pub bind_dn: String,
    pub bind_password: String,

    pub user_search_base_dn: Option<String>,
    pub user_search_filter: String,
    pub group_search_filter: String,
    pub group_search_base_dn: Option<String>,
    pub group_attribute: String,

    pub roles: HashMap<String, ReadWriteDefinition>,
}

fn escape_ldap_special_chars(input: &str) -> String {
    let mut output = String::new();
    for c in input.chars() {
        match c {
            '\\' => output.push_str("\\5c"),
            '*' => output.push_str("\\2a"),
            '(' => output.push_str("\\28"),
            ')' => output.push_str("\\29"),
            '\0' => output.push_str("\\00"),
            _ => output.push(c),
        }
    }
    output
}

#[cfg(feature = "ldap")]
async fn find_user_dn(
    ldap: &mut Ldap,
    ldap_config: &LdapConfig,
    uid: &str,
) -> Result<Option<String>> {
    //let filter = format!(&ldap_config.user_search_filter, uid);
    let filter = ldap_config
        .user_search_filter
        .replace("{}", escape_ldap_special_chars(&uid).as_str());

    let search_dn = match &ldap_config.user_search_base_dn {
        Some(dn) => dn,
        None => &ldap_config.base_dn,
    };

    trace!("Searching for user with {} in {}", &filter, search_dn);
    let (search_results, _ldap_result) = ldap
        .search(search_dn, Scope::Subtree, &filter, vec!["dn"])
        .await?
        .success()?;

    if search_results.len() != 1 {
        debug!("User not found or duplicate uid: {}", uid);
        return Ok(None);
    }
    match search_results.into_iter().next() {
        Some(search_result) => {
            let r = SearchEntry::construct(search_result);
            Ok(Some(r.dn))
        }
        None => {
            debug!("Error searching {}:", uid);
            Ok(None)
        }
    }
}

#[cfg(feature = "ldap")]
async fn get_user_groups(
    ldap: &mut Ldap,
    ldap_config: &LdapConfig,
    user_dn: &str,
) -> Result<Vec<String>> {
    let filter = ldap_config
        .group_search_filter
        .replace("{}", escape_ldap_special_chars(&user_dn).as_str());

    let search_dn = match &ldap_config.group_search_base_dn {
        Some(dn) => dn,
        None => &ldap_config.base_dn,
    };

    trace!("Searching for groups for user {} in {}", &filter, search_dn);

    let group_attribute = ldap_config.group_attribute.as_str();

    let (search_results, _res) = ldap
        .search(search_dn, Scope::Subtree, &filter, vec![group_attribute])
        .await?
        .success()?;

    let groups: Vec<String> = search_results
        .into_iter()
        .map(SearchEntry::construct)
        .map(|entry| {
            trace!("Found group: {:?}", entry);
            entry
        })
        .filter_map(|entry| {
            entry
                .attrs
                .get(group_attribute)
                .and_then(|vals| vals.first().cloned())
        })
        .collect();

    Ok(groups)
}

#[cfg(feature = "ldap")]
pub async fn authenticate_and_get_groups(
    ldap_config: &LdapConfig,
    user_uid: &str,
    user_password: &str,
) -> Result<Vec<String>> {
    trace!("opening ldap connection");
    let (conn, mut ldap) = LdapConnAsync::new(&ldap_config.ldap_url).await?;
    ldap3::drive!(conn);

    trace!("bind ldap connection");
    let bound = ldap.simple_bind(&ldap_config.bind_dn, user_password).await;
    trace!("searching bound={:?}, user {}", bound, &user_uid);
    if bound.is_err() {
        warn!("bind failed");
        return Ok(vec![]);
    }

    let user_dn = find_user_dn(&mut ldap, ldap_config, &user_uid).await?;

    match user_dn {
        None => {
            debug!("No user found");
            Ok(vec![])
        }
        Some(user_dn) => {
            debug!("found user {}", &user_dn);
            let try_to_bind = ldap.simple_bind(&user_dn, user_password).await?;
            if try_to_bind.rc != 0 {
                info!("bind failed for user {}", &user_dn);
                return Ok(vec![]);
            }
            let groups = get_user_groups(&mut ldap, ldap_config, &user_dn).await?;
            debug!("got groups {:?} for user {}", &groups, &user_uid);
            Ok(groups)
        }
    }
}

#[cfg(test)]
mod tests {
    use testcontainers::images::generic::GenericImage;

    use crate::ldap::{authenticate_and_get_groups, LdapConfig};

    use super::*;

    #[actix_web::test]
    #[cfg(feature = "ldap")]
    async fn test_ldap() {
        let docker = testcontainers::clients::Cli::default();
        let container = docker.run(
            GenericImage::new("bitnami/openldap", "latest")
                .with_env_var("LDAP_ORGANISATION", "My Company")
                .with_env_var("LDAP_ROOT", "dc=example,dc=com")
                .with_env_var("LDAP_DOMAIN", "example.com")
                .with_env_var("LDAP_ADMIN_USERNAME", "admin")
                .with_env_var("LDAP_ADMIN_PASSWORD", "adminpassword")
                .with_wait_for(testcontainers::core::WaitFor::message_on_stderr(
                    "slapd starting",
                )),
        );

        let port = container.get_host_port_ipv4(1389);
        let rw = ReadWriteDefinition {
            read: vec!["repo1:*".to_string()],
            write: vec!["repo2:*".to_string()],
        };

        let cfg = LdapConfig {
            ldap_url: format!("ldap://127.0.0.1:{}", port),
            bind_dn: "cn=admin,dc=example,dc=com".to_string(),
            bind_password: "adminpassword".to_string(),
            base_dn: "dc=example,dc=com".to_string(),
            group_search_filter: "(&(objectClass=groupOfNames)(member={}))".to_string(),
            group_attribute: "cn".to_string(),
            user_search_filter: "(&(objectClass=inetOrgPerson)(uid={}))".to_string(),
            group_search_base_dn: Some("dc=example,dc=com".to_string()),
            user_search_base_dn: Some("dc=example,dc=com".to_string()),
            roles: HashMap::from([("readers".to_string(), rw)]),
        };

        let groups = authenticate_and_get_groups(&cfg, "user02", "bitnami2")
            .await
            .unwrap();
        assert_eq!(groups, vec!["readers"]);
        info!("Groups: {:?}", groups);

        container.stop();
    }
}
