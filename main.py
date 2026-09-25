import hashlib
import math
from typing import Dict, Tuple

import requests
import streamlit as st
from zxcvbn import zxcvbn

st.set_page_config(
    page_title="Password Security Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown(
    """
    <style>
        :root {
            --bg: #0b1020;
            --panel: rgba(15, 23, 42, 0.7);
            --panel-strong: rgba(15, 23, 42, 0.85);
            --border: rgba(148, 163, 184, 0.18);
            --text: #e2e8f0;
            --muted: #94a3b8;
            --accent: #7c3aed;
            --accent-soft: rgba(124, 58, 237, 0.18);
            --success: #34d399;
            --warning: #fbbf24;
            --danger: #f87171;
        }

        .stApp {
            background: radial-gradient(circle at top left, rgba(124,58,237,0.25), transparent 28%),
                        radial-gradient(circle at bottom right, rgba(59,130,246,0.22), transparent 25%),
                        #020817;
            color: var(--text);
        }

        [data-testid="stAppViewContainer"] > .main {
            padding-top: 1.5rem;
        }

        .block-container {
            max-width: 1200px;
            padding-left: 2rem;
            padding-right: 2rem;
        }

        .glass-card {
            background: rgba(15, 23, 42, 0.75);
            border: 1px solid var(--border);
            border-radius: 20px;
            padding: 1.25rem 1.35rem;
            box-shadow: 0 16px 40px rgba(15, 23, 42, 0.3);
            backdrop-filter: blur(10px);
        }

        div[data-testid="stMetric"] {
            background: rgba(15, 23, 42, 0.72);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 0.9rem 1rem;
        }

        .security-meter {
            background: linear-gradient(90deg, #22c55e, #fbbf24, #f87171);
            height: 0.8rem;
            border-radius: 999px;
            overflow: hidden;
        }

        .status-badge {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 0.45rem 0.8rem;
            border-radius: 999px;
            font-weight: 700;
            letter-spacing: 0.02em;
        }

        .status-good {
            background: rgba(52, 211, 153, 0.12);
            color: var(--success);
            border: 1px solid rgba(52, 211, 153, 0.3);
        }

        .status-bad {
            background: rgba(248, 113, 113, 0.12);
            color: var(--danger);
            border: 1px solid rgba(248, 113, 113, 0.25);
        }

        .status-warn {
            background: rgba(251, 191, 36, 0.12);
            color: var(--warning);
            border: 1px solid rgba(251, 191, 36, 0.25);
        }

        .kicker {
            color: #a78bfa;
            text-transform: uppercase;
            letter-spacing: 0.12em;
            font-weight: 700;
            font-size: 0.72rem;
        }

        h1, h2, h3, h4 {
            color: #f8fafc !important;
            letter-spacing: -0.03em;
        }

        p, li, span, div {
            color: var(--text);
        }

        .stTextInput > div > div > input {
            border-radius: 12px;
            border: 1px solid rgba(148, 163, 184, 0.22);
            background: rgba(15, 23, 42, 0.8);
            color: #f8fafc;
            padding: 0.9rem 1rem;
        }

        .stAlert {
            border-radius: 14px;
        }
    </style>
    """,
    unsafe_allow_html=True,
)


def calculate_entropy(pwd: str) -> float:
    """Approximate password entropy in bits based on charset and length."""
    if not pwd:
        return 0.0

    pool_size = 0
    if any(char.islower() for char in pwd):
        pool_size += 26
    if any(char.isupper() for char in pwd):
        pool_size += 26
    if any(char.isdigit() for char in pwd):
        pool_size += 10
    if any(char in "!@#$%^&*()-_=+[]{}|;:,.<>/?" for char in pwd):
        pool_size += 32

    if pool_size == 0:
        return 0.0

    return round(len(pwd) * math.log2(pool_size), 2)


def check_pwned_api(pwd: str) -> int:
    """Query Have I Been Pwned using SHA-1 k-anonymity prefixing."""
    sha1 = hashlib.sha1(pwd.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    try:
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            return 0

        for line in response.text.splitlines():
            hash_suffix, count = line.split(":", 1)
            if hash_suffix == suffix:
                return int(count)
    except requests.RequestException as exc:
        st.warning(f"Unable to reach the breach API: {exc}")

    return 0


def get_strength_label(score: int) -> Tuple[str, str]:
    score_config = {
        0: ("Very Weak", "status-bad"),
        1: ("Weak", "status-bad"),
        2: ("Fair", "status-warn"),
        3: ("Strong", "status-good"),
        4: ("Very Strong", "status-good"),
    }
    return score_config.get(score, ("Unknown", "status-warn"))


st.title("🛡️ Password Security Analyzer")
st.caption("Check breach exposure, cracking difficulty, and password quality in real time.")

with st.container():
    st.markdown(
        """
        <div class="glass-card">
            <div class="kicker">Password review</div>
            <div style="margin-top: 0.5rem;">Enter a password below to analyze its strength.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

password = st.text_input("Password", type="password", placeholder="Type or paste a password", label_visibility="collapsed")

if password:
    with st.spinner("Analyzing your password against known breach and cracking data..."):
        breach_count = check_pwned_api(password)
        entropy = calculate_entropy(password)
        analysis = zxcvbn(password)

    score = analysis["score"]
    strength_label, badge_class = get_strength_label(score)

    col_a, col_b = st.columns([1.2, 1.8])

    with col_a:
        st.subheader("Summary")
        if breach_count > 0:
            st.markdown(
                f"<div class='status-badge status-bad'>🚨 Found in {breach_count:,} breach(es)</div>",
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                "<div class='status-badge status-good'>✅ Not found in public leaks</div>",
                unsafe_allow_html=True,
            )

        st.metric("Entropy", f"{entropy} bits")
        st.metric("Overall rating", strength_label)

        if entropy < 28:
            st.caption("🔴 Very low resistance to brute-force attacks.")
        elif entropy < 59:
            st.caption("🟡 Moderate strength, but still improvement is recommended.")
        else:
            st.caption("🟢 Strong entropy and good resistance to guessing attacks.")

    with col_b:
        st.subheader("Attack resistance")
        st.markdown(
            f"<div class='status-badge {badge_class}'>{strength_label}</div>",
            unsafe_allow_html=True,
        )

        meter_value = (score + 1) / 5 * 100
        st.markdown(f"<div class='security-meter' style='width: {meter_value}%;'></div>", unsafe_allow_html=True)

        times = analysis["crack_times_display"]
        st.markdown("### Estimated crack times")
        st.write(f"• **Fast GPU cluster:** {times['offline_fast_hashing_1e10_per_second']}")
        st.write(f"• **Slow hash / bcrypt:** {times['offline_slow_hashing_1e4_per_second']}")
        st.write(f"• **Unthrottled online attack:** {times['online_no_throttling_10_per_second']}")
        st.write(f"• **Throttled online attack:** {times['online_throttling_100_per_hour']}")

    st.divider()

    feedback = analysis["feedback"]
    advice = feedback.get("suggestions", [])
    warning = feedback.get("warning", "")

    if warning:
        st.warning(f"⚠️ {warning}")

    if advice:
        st.info("💡 Recommended improvements")
        for suggestion in advice:
            st.write(f"- {suggestion}")

    if not advice and not warning:
        st.success("✅ This password looks resilient and does not show obvious weakness patterns.")

else:
    st.info("Use the input above to evaluate a password and see a detailed security assessment.")