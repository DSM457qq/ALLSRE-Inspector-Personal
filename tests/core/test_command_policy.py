"""Compatibility tests for the retained, but runtime-unused, policy helpers."""

import pytest

from allsre_inspector.core.security import (
    classify_bash_command, command_denial_reason, command_is_mutating,
)


@pytest.mark.parametrize("command", [
    "command -v kubectl >/dev/null 2>&1 && kubectl version --client",
    "command -v docker 1>/dev/null 2>&1 && docker version",
    "cat /etc/os-release",
    "ip -o addr show | awk '{print $2, $4}'",
])
def test_read_only_inspection_commands_are_recognized(command):
    assert command_is_mutating(command) is False


@pytest.mark.parametrize("command", [
    "echo changed > /etc/example",
    "rm -f /tmp/file",
    "systemctl restart docker",
])
def test_mutating_commands_are_still_recognized_for_compatibility(command):
    assert command_is_mutating(command) is True


@pytest.mark.parametrize("command", [
    "docker --version", "docker -v", "docker --help", "nerdctl --version",
])
def test_read_only_container_version_queries_are_recognized(command):
    assert command_denial_reason(command, "READ_ONLY") is None


@pytest.mark.parametrize("command", [
    "systemctl is-active allsre-backend-test",
    "systemctl is-enabled allsre-backend-test",
    "ss -lntp | grep ':8010'",
    "ps -ef | grep java",
    "sleep 2",
    "ls; echo ok",
    "command -v docker && docker version --client",
    "git status",
    "docker ps",
    "kubectl get pods",
])
def test_bash_classifier_allows_only_read_only_commands(command):
    assert classify_bash_command(command)["classification"] == "READ_ONLY"


@pytest.mark.parametrize("command", [
    "systemctl restart sshd",
    "rm -f /tmp/file",
    "echo changed > /tmp/file",
    "useradd test",
    "curl -X POST http://example.invalid",
    "find /tmp -delete",
    "ls; rm -rf /tmp/x",
    "sh -c 'rm -rf /'",
])
def test_bash_classifier_requires_approval_for_mutation_or_unknown(command):
    assert classify_bash_command(command)["classification"] in {"MUTATING", "DESTRUCTIVE"}


@pytest.mark.parametrize("command", [
    "rm -rf /",
    "mkfs.ext4 /dev/sda1",
    "reboot",
])
def test_bash_classifier_hard_denies_destructive(command):
    decision = classify_bash_command(command)
    assert decision["classification"] == "DESTRUCTIVE"
    assert decision["policyVersion"] == "readonly-v4"


def test_bash_classifier_never_allows_empty_or_malformed():
    assert classify_bash_command("")["classification"] == "MUTATING"
    assert classify_bash_command("echo 'unterminated")["classification"] == "MUTATING"


@pytest.mark.parametrize("command", [
    "sed '1w /tmp/owned' /etc/hosts",
    "sed --in-place 's/a/b/' /etc/hosts",
    "sed '1e id' /etc/hosts",
    "awk 'BEGIN{print \"x\" > \"/tmp/owned\"}'",
    "awk 'BEGIN{\"id\" | getline x}'",
    "ip netns exec foo rm -rf /tmp/x",
    "ip -batch /tmp/commands",
    "ip --batch=/tmp/commands",
    "rpm -q --pipe sh",
    "git log --output=/tmp/owned",
    "git show --textconv HEAD",
    "sort -o /tmp/owned /etc/passwd",
    "sort --compress-program=sh /etc/passwd",
    "sar -o /tmp/owned 1 1",
    "hostname -b",
    "hostname --boot",
    "hostname -F /tmp/x",
    "file -C -m /tmp/magic",
    "iostat -o /tmp/x",
    "mpstat -o /tmp/x",
    "pidstat -o /tmp/x",
    "journalctl --sync",
    "iptables -L -F",
    "nft -f /tmp/rules list",
    "firewall-cmd --list-all --reload",
    "echo $(rm -rf /tmp/x)",
    "echo $(echo $(rm -rf /tmp/x))",
    "x=$(cat <(rm -rf /tmp/x))",
    "x=$(echo hi > /tmp/x)",
    "awk -v x=1 'BEGIN{system(\"id\")}' /proc/stat",
    "awk 'BEGIN{print \"x\" > \"/tmp/x\"}'",
    "tail -f /tmp/x",
    "journalctl -u sshd -f",
    "docker logs -f x",
    "kubectl logs -f x",
    "kubectl get pods -w",
    "ping 127.0.0.1",
    "top",
    "top -b",
])
def test_bash_classifier_never_allows_known_side_effect_forms(command):
    assert classify_bash_command(command)["classification"] != "READ_ONLY"


@pytest.mark.parametrize("command", [
    "timedatectl status",
    "localectl status",
    "loginctl list-sessions",
    "systemd-analyze blame",
    "file /etc/passwd",
    "who",
    "last -n 5",
    "w",
    "sar -f /tmp/data",
    "sort /etc/passwd",
    "ping -c 1 127.0.0.1",
    "dig example.com",
    "pidstat 1 1",
    "systemd-cgls",
    "dmidecode -t system",
    "hostname -f",
    "date +%s",
    "awk '{print $1}' /proc/stat",
    "awk -F: '{print $1}' /etc/passwd",
    "awk -v x=1 '{print x}' /proc/stat",
    "echo $(echo ok)",
    "docker -v",
    "tail -n 10 /tmp/x",
    "ping -c 1 127.0.0.1",
    "top -b -n 1",
    "journalctl -u sshd --no-pager -n 10",
    "docker logs --tail 10 x",
    "kubectl logs --tail=10 x",
    "journalctl -u sshd --no-pager",
    "iptables -L -n",
    "nft list ruleset",
    "firewall-cmd --list-all",
])
def test_bash_classifier_allows_read_only_forms(command):
    assert classify_bash_command(command)["classification"] == "READ_ONLY"


def test_bash_classifier_allows_read_only_system_snapshot():
    command = (
        "echo '=== OS ==='; grep -E '^(NAME|VERSION|PRETTY_NAME)=' /etc/os-release "
        "2>/dev/null; uname -a; awk '{printf \"%d\\n\", $1}' /proc/uptime; "
        "t1=$(awk '/^cpu /{s=0;for(i=2;i<=NF;i++)s+=$i;print s\" \"$5\" \"$6;exit}' "
        "/proc/stat); sleep 2; echo \"$t1\"; free -b | awk 'NR<=2'; "
        "systemctl is-active docker 2>&1; command -v docker >/dev/null && docker -v "
        "2>&1; __allsre_rc=$?;"
    )
    assert classify_bash_command(command)["classification"] == "READ_ONLY"
