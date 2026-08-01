#![forbid(unsafe_code)]

//! Fails if `.agents/skills/envault/SKILL.md` and the live CLI have drifted
//! apart (AXI guideline §7's "single source of truth" rule): each entry below
//! pins a literal substring the skill doc must still contain, and the
//! `--help` output the CLI must still produce for that command.

use std::process::Command;

const SKILL_MD: &str = include_str!("../../../.agents/skills/envault/SKILL.md");

struct Reference {
    doc_substring: &'static str,
    help_args: &'static [&'static str],
    help_must_contain: &'static [&'static str],
}

const REFERENCES: &[Reference] = &[
    Reference {
        doc_substring: "envault session setup",
        help_args: &["session", "setup", "--help"],
        help_must_contain: &["Installs a SessionStart hook"],
    },
    Reference {
        doc_substring: "envault --output toon status",
        help_args: &["--help"],
        help_must_contain: &["--output", "status"],
    },
    Reference {
        doc_substring: "envault start",
        help_args: &["start", "--help"],
        help_must_contain: &["Usage: envault start"],
    },
    Reference {
        doc_substring: "envault profile load",
        help_args: &["profile", "load", "--help"],
        help_must_contain: &["Usage: envault profile load"],
    },
    Reference {
        doc_substring: "workspace load",
        help_args: &["workspace", "load", "--help"],
        help_must_contain: &["Usage: envault workspace load"],
    },
    Reference {
        doc_substring: "envault --output toon secret list --fields description",
        help_args: &["secret", "list", "--help"],
        help_must_contain: &["--fields", "--profile"],
    },
    Reference {
        doc_substring: "envault run --profile <name> -- <command> [args...]",
        help_args: &["run", "--help"],
        help_must_contain: &["--profile", "--workspace"],
    },
];

#[test]
fn skill_doc_matches_live_cli() {
    for reference in REFERENCES {
        assert!(
            SKILL_MD.contains(reference.doc_substring),
            "SKILL.md no longer mentions `{}`; update the doc or this test",
            reference.doc_substring
        );

        let output = Command::new(env!("CARGO_BIN_EXE_envault"))
            .args(reference.help_args)
            .output()
            .expect("run envault --help");
        assert!(
            output.status.success(),
            "`envault {}` failed: {}",
            reference.help_args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
        let help_text = String::from_utf8_lossy(&output.stdout);
        for expected in reference.help_must_contain {
            assert!(
                help_text.contains(expected),
                "SKILL.md documents `{}` but `envault {} --help` no longer mentions `{}`:\n{}",
                reference.doc_substring,
                reference.help_args.join(" "),
                expected,
                help_text
            );
        }
    }
}
