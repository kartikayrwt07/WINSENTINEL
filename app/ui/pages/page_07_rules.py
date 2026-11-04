"""Page 7: Detection Rule Catalog View."""

from __future__ import annotations

from typing import Any

try:
    import streamlit as st
    HAS_STREAMLIT = True
except ImportError:
    st = None
    HAS_STREAMLIT = False

from app.database.connection import DatabaseManager
from app.ui.components.badges import render_mitre_pill, render_severity_pill, render_status_pill
from app.ui.components.tables import format_table_html
from app.ui.services.rule_ui_service import RuleUIService


def render_page(db_manager: DatabaseManager | None = None) -> dict[str, Any]:
    """Render the Detection Rule Catalog and inspection view."""
    service = RuleUIService(rules_dir="rules/sysmon", db_manager=db_manager)

    cat_filter = "ALL"
    sev_filter = "ALL"
    search_query = None

    if HAS_STREAMLIT and st is not None:
        st.markdown("## 🛡️ Detection Rule Catalog")
        st.caption("Inspect active Sigma-inspired detection rules, AST condition logic, and investigation runbooks.")

        c1, c2, c3 = st.columns([1, 1, 2])
        with c1:
            cat_filter = st.selectbox(
                "Category",
                ["ALL", "process_creation", "network_connection", "image_load", "remote_thread", "process_access", "registry", "dns_query"],
                index=0,
            )
        with c2:
            sev_filter = st.selectbox(
                "Severity",
                ["ALL", "critical", "high", "medium", "low", "informational"],
                index=0,
            )
        with c3:
            search_query = st.text_input("Search Rules", placeholder="e.g. certutil or T1105") or None

    rules = service.list_rules(
        category=cat_filter if cat_filter != "ALL" else None,
        severity=sev_filter if sev_filter != "ALL" else None,
        search=search_query,
    )

    selected_detail = None
    yaml_content = ""

    if HAS_STREAMLIT and st is not None:
        st.markdown(f"**Loaded Rules ({len(rules)})**")

        if rules:
            headers = ["Rule ID", "Severity", "Category", "EID", "Title", "MITRE ATT&CK", "Author"]
            rows = []
            for r in rules:
                sev_html = render_severity_pill(r["severity"])
                mitre_html = " ".join([render_mitre_pill(t) for t in r["mitre_attack"]]) if r["mitre_attack"] else "-"
                rows.append([
                    f"<code>{r['id']}</code>",
                    sev_html,
                    r["category"],
                    str(r["event_id"] or "-"),
                    r["title"],
                    mitre_html,
                    r["author"],
                ])

            st.markdown(format_table_html(headers, rows), unsafe_allow_html=True)

            rule_choices = [f"{r['id']} — {r['title']}" for r in rules]
            sel_idx = st.selectbox("Inspect Rule Definition", range(len(rule_choices)), format_func=lambda i: rule_choices[i])
            chosen_id = rules[sel_idx]["id"]

            selected_detail = service.get_rule_detail(chosen_id)
            yaml_content = service.get_rule_yaml(chosen_id)

            if selected_detail:
                st.divider()
                st.markdown(f"### 📋 {selected_detail['id']}: {selected_detail['title']}")
                st.write(selected_detail["description"])

                tab_logic, tab_yaml, tab_steps = st.tabs(["Logic & Condition", "Raw YAML Definition", "Investigation Steps"])

                with tab_logic:
                    col_cond, col_sel = st.columns(2)
                    with col_cond:
                        st.markdown("**Boolean Condition:**")
                        st.code(selected_detail["condition"], language="python")
                        st.markdown(f"**Log Source:** `{selected_detail.get('product')}` / `{selected_detail.get('service')}` (Event ID `{selected_detail.get('event_id')}`)")
                    with col_sel:
                        st.markdown("**Selection Criteria:**")
                        st.json(selected_detail["selections"])

                with tab_yaml:
                    st.code(yaml_content, language="yaml")

                with tab_steps:
                    steps = selected_detail.get("investigation_steps", [])
                    if steps:
                        for idx, step in enumerate(steps, 1):
                            st.markdown(f"{idx}. {step}")
                    else:
                        st.info("No explicit investigation steps defined for this rule.")
        else:
            st.info("No detection rules match the specified criteria.")

    return {
        "rules": rules,
        "selected_detail": selected_detail,
        "yaml_content": yaml_content,
    }

