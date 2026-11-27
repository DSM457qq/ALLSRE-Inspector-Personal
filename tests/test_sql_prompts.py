from pathlib import Path


SOURCE = Path(__file__).resolve().parents[1] / "allsre_inspector" / "securecrt_bridge" / "securecrt_bridge_v2.py"


def test_mysql_and_mariadb_prompts_are_recognized():
    source = SOURCE.read_text(encoding="utf-8")
    for prompt in ('"mysql> "', '"mysql>"', '"MariaDB ["', '"mariadb> "', '"mariadb>"'):
        assert prompt in source


def test_oracle_and_shell_prompts_remain_recognized():
    source = SOURCE.read_text(encoding="utf-8")
    for prompt in ('"SQL> "', '"SQL>"', '"# "', '"$ "'):
        assert prompt in source
