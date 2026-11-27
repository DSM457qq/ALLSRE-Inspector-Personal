from allsre_inspector.core.readonly_policy import classify_bash_command


def classification(command: str) -> str:
    return classify_bash_command(command)["classification"]


def test_systemctl_failed_is_read_only():
    assert classification("systemctl --failed") == "READ_ONLY"
    assert classification("systemctl --no-pager --failed") == "READ_ONLY"
    assert classification("systemctl --state=failed") == "READ_ONLY"


def test_systemctl_failed_with_mutating_verb_stays_mutating():
    assert classification("systemctl --failed restart nginx") == "MUTATING"
