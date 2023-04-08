use std::collections::HashMap;

use log::{debug, trace};
use regex::Regex;

#[derive(Debug, Clone)]
pub struct GroupPermissions {
    pub permissions_by_group: HashMap<String, ReadWritePermissions>,
}

impl GroupPermissions {
    pub fn new(group_permissions: HashMap<String, ReadWritePermissions>) -> Self {
        Self {
            permissions_by_group: group_permissions.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
        }
    }

    fn can_access(&self, groups: Vec<String>, path: &str, check_function: fn(&ReadWritePermissions, &str) -> bool) -> bool {
        for group in groups {
            if let Some(permissions) = self.permissions_by_group.get(&group) {
                if check_function(permissions, path) {
                    return true;
                }
            }
        }
        false
    }


    pub fn can_read(&self, groups: Vec<String>, path: &str) -> bool {
        self.can_access(groups, path, |permissions, path| permissions.can_read(path))
    }

    pub fn can_write(&self, groups: Vec<String>, path: &str) -> bool {
        self.can_access(groups, path, |permissions, path| permissions.can_write(path))
    }
}


#[derive(Debug, Clone)]
pub struct ReadWritePermissions {
    read: Permissions,
    write: Permissions,
}

impl ReadWritePermissions {
    pub fn new(read_perm_list: &Vec<String>, write_perm_list: &Vec<String>) -> Self {
        Self {
            read: Permissions::new(read_perm_list),
            write: Permissions::new(write_perm_list),
        }
    }

    fn can_read(&self, path: &str) -> bool {
        self.read.is_allowed(path)
    }
    fn can_write(&self, path: &str) -> bool {
        self.write.is_allowed(path)
    }
}

#[derive(Debug, Clone)]
struct Permissions {
    allow: Vec<Regex>,
    deny: Vec<Regex>,
}

impl Permissions {
    fn convert_glob_to_regex(glob_pattern: &str) -> String {
        let mut regex = String::new();
        for c in glob_pattern.chars() {
            match c {
                '*' => regex.push_str(".*"),
                '?' => regex.push('.'),
                '.' => regex.push_str("\\."),
                '\\' => regex.push_str("\\\\"),
                '/' => regex.push('/'),
                '^' => regex.push_str("\\^"),
                '(' => regex.push_str("\\("),
                ')' => regex.push_str("\\)"),
                _ => regex.push(c),
            }
        }
        regex
    }

    fn new(glob_pattern: &Vec<String>) -> Self {
        let mut allow = Vec::new();
        let mut deny = Vec::new();
        for str in glob_pattern {
            let str = Self::convert_glob_to_regex(str);
            if str.starts_with('!') {
                deny.push(Regex::new(str.strip_prefix('!').unwrap()).unwrap());
            } else {
                allow.push(Regex::new(&str).unwrap());
            }
        }

        Self {
            allow,
            deny,
        }
    }

    fn is_allowed(&self, path: &str) -> bool {
        // allow has precedence over allow
        for regex in &self.allow {
            if regex.is_match(path) {
                trace!("allow: {} matches {}", path, regex.as_str());
                return true;
            }
        }
        for regex in &self.deny {
            if regex.is_match(path) {
                debug!("deny: {} matches {}", path, regex.as_str());
                return false;
            }
        }
        // if no allow rule matches, deny by default
        debug!("deny: {} matches no allow rule", path);
        false
    }
}

#[cfg(test)]
mod test {
    use crate::perm::{Permissions, ReadWritePermissions};

    #[test]
    fn test_patterns() {
        let p = Permissions::new(&vec![
            "repo1:*:*-SNAPSHOT".to_string(),
            "!repo1:foo/bar:*".to_string(),
        ]);
        assert!(p.is_allowed("repo1:foo/bar:1.0-SNAPSHOT"));
        assert!(!p.is_allowed("repo1:foo/bar:1.0"));
    }

    #[test]
    fn test_perm_list() {
        let perm_list = vec!["repo1:*:*-SNAPSHOT".to_string(), "!repo1:foo/bar:*".to_string()];
        let gp = ReadWritePermissions::new(&perm_list, &vec!());
        assert!(gp.can_read("repo1:foo/bar:1.0-SNAPSHOT"));
        assert!(!gp.can_write("repo2:foo/bar:1.0-SNAPSHOT"));
    }
}