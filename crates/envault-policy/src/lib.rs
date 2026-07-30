#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    pub effect: Effect,
    pub principal: String,
    pub action: String,
    pub resource: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    Allow,
    DenyExplicit,
    DenyDefault,
}

#[must_use]
pub fn evaluate(rules: &[Rule], principal: &str, action: &str, resource: &str) -> Decision {
    let matching = rules.iter().filter(|rule| {
        rule.principal == principal && rule.action == action && rule.resource == resource
    });
    let mut allowed = false;
    for rule in matching {
        match rule.effect {
            Effect::Deny => return Decision::DenyExplicit,
            Effect::Allow => allowed = true,
        }
    }
    if allowed {
        Decision::Allow
    } else {
        Decision::DenyDefault
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_always_wins() {
        let rules = [
            Rule {
                effect: Effect::Allow,
                principal: "agent:codex".into(),
                action: "http.request".into(),
                resource: "openai".into(),
            },
            Rule {
                effect: Effect::Deny,
                principal: "agent:codex".into(),
                action: "http.request".into(),
                resource: "openai".into(),
            },
        ];
        assert_eq!(
            evaluate(&rules, "agent:codex", "http.request", "openai"),
            Decision::DenyExplicit
        );
    }

    #[test]
    fn no_match_is_denied() {
        assert_eq!(
            evaluate(&[], "agent:x", "read", "secret"),
            Decision::DenyDefault
        );
    }
}
