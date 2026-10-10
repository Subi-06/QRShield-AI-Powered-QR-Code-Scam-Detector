"""Scan History page for QRShield AI.

Provides comprehensive exploration, search, filtering, inspection, and
management of past QR code security scans and threat assessments.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

import streamlit as st

# Ensure project root is on Python module search path
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from config.settings import (
    APP_NAME,
    DANGER_RED,
    DARK_BLUE,
    LIGHT_BG,
    MUTED_GRAY,
    NAVY,
    SUCCESS_GREEN,
    WARNING_AMBER,
)
from src.database.db_manager import DatabaseManager
from src.security.sanitizer import InputSanitizer

st.set_page_config(
    page_title=f"{APP_NAME} - History",
    page_icon="🛡️",
    layout="wide",
)

# Custom Styling
st.markdown(
    """
    <style>
    .history-header {
        margin-bottom: 1.5rem;
    }
    .history-header h1 {
        font-size: 2.2rem;
        font-weight: 700;
        color: #0A192F;
        margin-bottom: 0.25rem;
    }
    .history-header p {
        font-size: 1rem;
        color: #64748B;
        margin-top: 0;
    }
    .filter-container {
        background-color: #F8FAFC;
        border: 1px solid #E2E8F0;
        border-radius: 10px;
        padding: 1.25rem;
        margin-bottom: 1.5rem;
    }
    .stats-badge {
        display: inline-block;
        padding: 0.2rem 0.6rem;
        border-radius: 6px;
        font-size: 0.85rem;
        font-weight: 600;
    }
    .pagination-bar {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-top: 1.5rem;
        margin-bottom: 1.5rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource
def get_db_manager() -> DatabaseManager:
    """Retrieve or initialize the DatabaseManager instance."""
    return DatabaseManager()


db = get_db_manager()


def render_header() -> None:
    """Render the page header section."""
    st.markdown(
        """
        <div class="history-header">
            <h1>📜 Scan History</h1>
            <p>View, search, and manage your past QR code scans</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def scan_card(scan: Dict[str, Any]) -> None:
    """Render a styled summary card for an individual scan record.

    Args:
        scan: Scan record dictionary.
    """
    risk_colors = {
        "low_risk": ("#00C853", "Low Risk", "✅"),
        "suspicious": ("#FFB300", "Suspicious", "⚠️"),
        "high_risk": ("#FF1744", "High Risk", "🚨"),
        "verification_required": ("#2196F3", "Verification Required", "🔍"),
    }
    raw_risk = str(scan.get("risk_level") or "").lower().strip()
    color, label, icon = risk_colors.get(raw_risk, ("#6c757d", "Unknown", "❓"))

    raw_preview = scan.get("content_preview") or "N/A"
    safe_preview = InputSanitizer.sanitize_for_display(str(raw_preview), max_length=200)

    raw_content_type = str(scan.get("content_type") or "Unknown")
    safe_content_type = InputSanitizer.sanitize_text(raw_content_type).upper()

    raw_timestamp = str(scan.get("timestamp") or "")
    safe_timestamp = InputSanitizer.sanitize_text(raw_timestamp)

    st.markdown(
        f"""
        <div style="background: white; border-radius: 12px; padding: 1.5rem; 
                    margin-bottom: 0.5rem; box-shadow: 0 2px 8px rgba(0,0,0,0.06);
                    border-left: 4px solid {color}; border: 1px solid #E2E8F0;
                    border-left-width: 6px;">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 0.5rem;">
                <div>
                    <span style="background: {color}20; color: {color}; padding: 0.25rem 0.75rem; 
                                 border-radius: 20px; font-size: 0.85rem; font-weight: 600;">
                        {icon} {label}
                    </span>
                    <span style="color: #64748B; margin-left: 0.8rem; font-size: 0.85rem; font-weight: 500;">
                        {safe_content_type}
                    </span>
                </div>
                <span style="color: #94A3B8; font-size: 0.85rem; font-family: sans-serif;">{safe_timestamp}</span>
            </div>
            <p style="margin: 0.75rem 0 0 0; color: #1E293B; font-family: monospace; 
                      font-size: 0.9rem; word-break: break-all;">
                {safe_preview}
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_empty_state() -> None:
    """Render empty state placeholder when no scan records match."""
    st.markdown(
        """
        <div style="text-align: center; padding: 3.5rem 1rem; background: #FFFFFF; border-radius: 12px; border: 1px dashed #CBD5E1; margin: 1.5rem 0;">
            <div style="font-size: 3.5rem; margin-bottom: 0.5rem;">📜</div>
            <h3 style="color: #475569; font-weight: 600; margin-bottom: 0.25rem;">No Scan History</h3>
            <p style="color: #94A3B8; font-size: 0.95rem; margin: 0;">Your scan history will appear here after analyzing QR codes.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def parse_json_safely(raw_data: Any) -> Any:
    """Parse JSON strings safely or return as-is if already deserialized."""
    if isinstance(raw_data, str):
        try:
            return json.loads(raw_data)
        except Exception:
            return raw_data
    return raw_data


def render_scan_details(scan: Dict[str, Any]) -> None:
    """Render detailed expander view for a scan record.

    Args:
        scan: Scan record dictionary.
    """
    scan_id = scan.get("scan_id", "")
    full_content = scan.get("full_content") or scan.get("content_preview") or "No content available"
    sanitized_full_content = InputSanitizer.sanitize_text(str(full_content))

    indicators = parse_json_safely(scan.get("risk_indicators"))
    explanation = scan.get("explanation_summary")
    model_prob = scan.get("model_probability")
    risk_score = scan.get("risk_score")
    model_version = scan.get("model_version")
    features = parse_json_safely(scan.get("features_json"))
    category = scan.get("prediction_category")

    col1, col2, col3 = st.columns([1, 1, 1])
    with col1:
        st.caption("Scan ID")
        st.code(scan_id, language=None)
    with col2:
        st.caption("Prediction Category")
        st.write(f"**{category or 'N/A'}**")
    with col3:
        st.caption("Model Probability / Risk Score")
        prob_str = f"{model_prob * 100:.1f}%" if model_prob is not None else "N/A"
        score_str = f"{risk_score:.2f}" if risk_score is not None else "N/A"
        st.write(f"Prob: **{prob_str}** | Score: **{score_str}**")

    st.markdown("**Full Decoded Content:**")
    st.text_area(
        label=f"Content for {scan_id}",
        value=sanitized_full_content,
        height=90,
        disabled=True,
        label_visibility="collapsed",
        key=f"content_area_{scan_id}",
    )

    if explanation:
        st.markdown("**Threat Explanation Summary:**")
        st.info(InputSanitizer.sanitize_text(str(explanation)))

    if indicators:
        st.markdown("**Risk Indicators Detected:**")
        if isinstance(indicators, list):
            for ind in indicators:
                if isinstance(ind, dict):
                    ind_text = ind.get("indicator") or ind.get("name") or json.dumps(ind)
                    severity = ind.get("severity", "info").lower()
                    if severity in ("high", "critical"):
                        st.error(f"🚨 {InputSanitizer.sanitize_text(str(ind_text))}")
                    elif severity in ("warning", "suspicious", "medium"):
                        st.warning(f"⚠️ {InputSanitizer.sanitize_text(str(ind_text))}")
                    else:
                        st.info(f"ℹ️ {InputSanitizer.sanitize_text(str(ind_text))}")
                else:
                    st.write(f"• {InputSanitizer.sanitize_text(str(ind))}")
        elif isinstance(indicators, dict):
            st.json(indicators)
        else:
            st.write(InputSanitizer.sanitize_text(str(indicators)))

    if features and isinstance(features, dict) and len(features) > 0:
        with st.expander("Extracted Features & Model Metadata"):
            if model_version:
                st.write(f"**Model Version:** `{model_version}`")
            st.json(features)

    # Individual scan deletion action
    del_col1, del_col2 = st.columns([6, 1])
    with del_col2:
        confirm_del_key = f"confirm_del_{scan_id}"
        if not st.session_state.get(confirm_del_key, False):
            if st.button("🗑️ Delete", key=f"btn_del_{scan_id}", help="Delete this scan"):
                st.session_state[confirm_del_key] = True
                st.rerun()
        else:
            st.warning("Confirm?")
            c1, c2 = st.columns(2)
            with c1:
                if st.button("Yes", key=f"btn_yes_{scan_id}", type="primary"):
                    try:
                        db.delete_scan(scan_id)
                        st.session_state[confirm_del_key] = False
                        st.toast("Scan deleted successfully", icon="✅")
                        st.rerun()
                    except Exception as err:
                        st.error(f"Error deleting scan: {err}")
            with c2:
                if st.button("No", key=f"btn_no_{scan_id}"):
                    st.session_state[confirm_del_key] = False
                    st.rerun()


def fetch_scans(
    search_query: str,
    content_type_filter: str,
    risk_level_filter: str,
    start_date: Optional[date],
    end_date: Optional[date],
) -> List[Dict[str, Any]]:
    """Retrieve and filter scans from the database based on criteria.

    Args:
        search_query: Text substring to match.
        content_type_filter: Selected content type (or 'All').
        risk_level_filter: Selected risk level (or 'All').
        start_date: Optional start date.
        end_date: Optional end date.

    Returns:
        List of matching scan dictionaries.
    """
    try:
        # Determine query parameters for DatabaseManager
        c_type = None if content_type_filter == "All" else content_type_filter.lower()
        
        # Map user-friendly risk levels to DB representations
        risk_map = {
            "All": None,
            "Low Risk": "low_risk",
            "Suspicious": "suspicious",
            "High Risk": "high_risk",
            "Verification Required": "verification_required",
        }
        r_level = risk_map.get(risk_level_filter)

        start_str = f"{start_date.isoformat()}T00:00:00" if start_date else None
        end_str = f"{end_date.isoformat()}T23:59:59" if end_date else None

        # Fetch records using database filtering
        records = db.filter_scans(
            content_type=c_type,
            risk_level=r_level,
            start_date=start_str,
            end_date=end_str,
        )

        # Apply search text query if provided
        if search_query:
            query_lower = search_query.strip().lower()
            filtered: List[Dict[str, Any]] = []
            for item in records:
                preview = str(item.get("content_preview") or "").lower()
                full = str(item.get("full_content") or "").lower()
                cat = str(item.get("prediction_category") or "").lower()
                exp = str(item.get("explanation_summary") or "").lower()
                sid = str(item.get("scan_id") or "").lower()
                if (
                    query_lower in preview
                    or query_lower in full
                    or query_lower in cat
                    or query_lower in exp
                    or query_lower in sid
                ):
                    filtered.append(item)
            return filtered

        return records
    except Exception as e:
        st.error(f"Database error while querying scans: {e}")
        return []


def main() -> None:
    """Main execution entry point for History page."""
    render_header()

    # Session state initialization for management and pagination
    if "history_page" not in st.session_state:
        st.session_state["history_page"] = 1
    if "show_clear_confirm" not in st.session_state:
        st.session_state["show_clear_confirm"] = False
    if "selected_scan_ids" not in st.session_state:
        st.session_state["selected_scan_ids"] = set()

    # Filter Bar
    with st.container():
        col_search, col_type, col_risk, col_date = st.columns([3, 2, 2, 3])

        with col_search:
            search_input = st.text_input(
                "🔍 Search Content",
                placeholder="Search text, URL, UPI, keyword...",
                key="filter_search",
            )

        with col_type:
            content_type_options = ["All", "URL", "UPI", "Text", "Email", "Phone", "WiFi", "vCard", "Geo"]
            content_type_sel = st.selectbox(
                "📂 Content Type",
                options=content_type_options,
                index=0,
                key="filter_content_type",
            )

        with col_risk:
            risk_level_options = ["All", "Low Risk", "Suspicious", "High Risk", "Verification Required"]
            risk_level_sel = st.selectbox(
                "🛡️ Risk Level",
                options=risk_level_options,
                index=0,
                key="filter_risk_level",
            )

        with col_date:
            default_start = date.today() - timedelta(days=30)
            default_end = date.today()
            date_range = st.date_input(
                "📅 Date Range",
                value=(default_start, default_end),
                max_value=date.today(),
                key="filter_date_range",
            )

    start_d: Optional[date] = None
    end_d: Optional[date] = None
    if isinstance(date_range, (tuple, list)):
        if len(date_range) >= 1:
            start_d = date_range[0]
        if len(date_range) >= 2:
            end_d = date_range[1]
    elif isinstance(date_range, date):
        start_d = date_range
        end_d = date_range

    # Fetch matching records
    all_matching_scans = fetch_scans(
        search_query=search_input,
        content_type_filter=content_type_sel,
        risk_level_filter=risk_level_sel,
        start_date=start_d,
        end_date=end_d,
    )

    total_scans = len(all_matching_scans)
    page_size = 20
    max_pages = max(1, (total_scans + page_size - 1) // page_size)

    # Ensure page is within valid range
    if st.session_state["history_page"] > max_pages:
        st.session_state["history_page"] = max_pages
    if st.session_state["history_page"] < 1:
        st.session_state["history_page"] = 1

    current_page = st.session_state["history_page"]

    # Top Control and Summary Bar
    st.markdown("---")
    ctrl_col1, ctrl_col2, ctrl_col3 = st.columns([4, 2, 2])

    with ctrl_col1:
        st.markdown(
            f"**Total Records:** `{total_scans}` &nbsp;|&nbsp; Page **{current_page}** of **{max_pages}**"
        )

    with ctrl_col2:
        if st.session_state.get("selected_scan_ids"):
            sel_count = len(st.session_state["selected_scan_ids"])
            if st.button(f"🗑️ Delete Selected ({sel_count})", type="secondary"):
                try:
                    deleted_count = 0
                    for s_id in list(st.session_state["selected_scan_ids"]):
                        if db.delete_scan(s_id):
                            deleted_count += 1
                    st.session_state["selected_scan_ids"].clear()
                    st.success(f"Deleted {deleted_count} scan(s).")
                    st.rerun()
                except Exception as ex:
                    st.error(f"Error deleting selected scans: {ex}")

    with ctrl_col3:
        if not st.session_state["show_clear_confirm"]:
            if st.button("🗑️ Clear All History", type="secondary", use_container_width=True):
                st.session_state["show_clear_confirm"] = True
                st.rerun()
        else:
            st.warning("Permanently delete all scan records?")
            conf_c1, conf_c2 = st.columns(2)
            with conf_c1:
                if st.button("Confirm Delete All", type="primary", use_container_width=True):
                    try:
                        cleared_count = db.clear_history()
                        st.session_state["show_clear_confirm"] = False
                        st.session_state["selected_scan_ids"].clear()
                        st.success(f"History cleared ({cleared_count} records removed).")
                        st.rerun()
                    except Exception as ex:
                        st.error(f"Error clearing history: {ex}")
            with conf_c2:
                if st.button("Cancel", use_container_width=True):
                    st.session_state["show_clear_confirm"] = False
                    st.rerun()

    if total_scans == 0:
        render_empty_state()
        return

    # Slice scans for current page
    start_idx = (current_page - 1) * page_size
    end_idx = min(start_idx + page_size, total_scans)
    page_scans = all_matching_scans[start_idx:end_idx]

    # Render Scans
    for scan in page_scans:
        s_id = scan.get("scan_id", "")
        row_c1, row_c2 = st.columns([0.04, 0.96])
        with row_c1:
            st.write("")
            is_checked = s_id in st.session_state["selected_scan_ids"]
            if st.checkbox("", value=is_checked, key=f"chk_{s_id}", label_visibility="collapsed"):
                st.session_state["selected_scan_ids"].add(s_id)
            else:
                st.session_state["selected_scan_ids"].discard(s_id)

        with row_c2:
            scan_card(scan)
            with st.expander("🔍 View Detailed Analysis & Actions", expanded=False):
                render_scan_details(scan)

    # Pagination Navigation
    st.markdown("---")
    p_col1, p_col2, p_col3, p_col4, p_col5 = st.columns([2, 1, 2, 1, 2])

    with p_col2:
        if st.button("⬅️ Previous", disabled=(current_page <= 1), use_container_width=True):
            st.session_state["history_page"] = current_page - 1
            st.rerun()

    with p_col3:
        st.markdown(
            f"<div style='text-align: center; padding-top: 0.4rem; color: #64748B; font-weight: 500;'>"
            f"Showing {start_idx + 1}–{end_idx} of {total_scans} scans (Page {current_page}/{max_pages})"
            f"</div>",
            unsafe_allow_html=True,
        )

    with p_col4:
        if st.button("Next ➡️", disabled=(current_page >= max_pages), use_container_width=True):
            st.session_state["history_page"] = current_page + 1
            st.rerun()


if __name__ == "__main__":
    main()
