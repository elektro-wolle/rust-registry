#[cfg(feature = "ldap")]
use ldap3::{Ldap, LdapConnAsync, Scope, SearchEntry};
#[cfg(feature = "ldap")]
use ldap3::result::Result;
#[cfg(feature = "ldap")]
use log::debug;
#[cfg(feature = "ldap")]
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg(feature = "ldap")]
pub struct LdapConfig {
    pub ldap_url: String,
    pub base_dn: String,
    pub bind_dn: String,
    pub bind_password: String,

    pub user_search_base_dn: String,
    pub user_search_filter: String,
    pub group_search_filter: String,
    pub group_search_base_dn: String,
    pub group_attribute: String,
}

#[cfg(feature = "ldap")]
async fn find_user_dn(
    ldap: &mut Ldap,
    ldap_config: &LdapConfig,
    uid: &str,
) -> Result<Option<String>> {
    //let filter = format!(&ldap_config.user_search_filter, uid);
    let filter = format!("(&(objectClass=inetOrgPerson)(uid={}))", &uid);

    let (search_results, _ldap_result) = ldap
        .search(&ldap_config.base_dn, Scope::Subtree, &filter, vec!["dn"])
        .await?.success()?;

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
    // let r = SearchEntry::construct(search_results[0]);
    //

    // if let Some(user_entry) = search_results.into_iter().next() {
    //     Ok(user_entry.dn)
    // } else {
    //     Err("User not found".into())
    // }

    // if let Some(user_entry) = search_results.into_iter().next() {
    //     Ok(user_entry.dn)
    // } else {
    //     Err("User not found".into())
    // }
}

#[cfg(feature = "ldap")]
async fn get_user_groups(
    ldap: &mut Ldap,
    ldap_config: &LdapConfig,
    user_dn: &str,
) -> Result<Vec<String>> {
    // let filter = format!(ldap_config.group_search_filter, user_dn);
    let filter = format!("(&(objectClass=groupOfNames)(member={}))", user_dn);
    debug!("Searching for groups for user {}", &filter);
    let (search_results, _res) = ldap
        .search(&ldap_config.base_dn, Scope::Subtree, &filter, vec!["cn"])
        .await?.success()?;

    let groups: Vec<String> = search_results
        .into_iter()
        .map(SearchEntry::construct)
        .map(|entry| {
            debug!("Found group: {:?}", entry);
            entry
        })
        .filter_map(|entry| entry.attrs.get("cn").and_then(|vals| vals.first().cloned()))
        .collect();

    Ok(groups)
}

#[cfg(feature = "ldap")]
pub async fn authenticate_and_get_groups(
    ldap_config: &LdapConfig,
    user_uid: &str,
    user_password: &str,
) -> Result<Vec<String>> {
    debug!("opening ldap connection");
    let (conn, mut ldap) = LdapConnAsync::new(&ldap_config.ldap_url)
        .await?;
    ldap3::drive!(conn);

    debug!("bind ldap connection");
    let bound = ldap.simple_bind(&ldap_config.bind_dn, user_password).await;

    debug!("searching bound={:?}, user {}", bound, &user_uid);

    let user_dn = find_user_dn(&mut ldap, ldap_config, &user_uid).await?;
    match user_dn {
        None => {
            debug!("No user found");
            Ok(vec![])
        }
        Some(user_dn) => {
            debug!("found user {}", &user_dn);
            ldap.simple_bind(&user_dn, user_password).await?;
            debug!("bound user {}", &user_dn);
            let groups = get_user_groups(&mut ldap, ldap_config, &user_dn).await?;
            debug!("got groups {:?}", &groups);
            // ldap.unbind().await?;
            Ok(groups)
        }
    }
    // if user_dn.is_none() {
    //     return Ok(vec![]);
    // }
    //
    // ldap.simple_bind(&user_dn, &user_password).await?;
    // let groups = get_user_groups(&mut ldap, &ldap_config, &user_dn).await?;
    //
    // Ok(groups)
}
//
// #[tokio::main]
// async fn main() {
//     let ldap_url = "ldap://ldap.example.com";
//     let bind_dn = "cn=admin,dc=example,dc=com";
//     let bind_password = "admin_password";
//     let user_uid = "user@example.com";
//     let user_password = "user_password";
//     let user_base_dn = "ou=users,dc=example,dc=com";
//     let group_base_dn = "ou=groups,dc=example,dc=com";
//
//     match authenticate_and_get_groups(
//         ldap_url,
//         bind_dn,
//         bind_password,
//         user_uid,
//         user_password,
//         user_base_dn,
//         group_base_dn,
//     )
//         .await
//     {
//         Ok(groups) => println!("Groups: {:?}", groups),
//         Err(err) => println!("Error: {}", err),
//     }
// }
