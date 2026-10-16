"""
DeveloperOS Cryptography & Security Suite - Interactive Application
"""

import streamlit as st
from core.hasher import compute_hashes
from ui.components import render_suite_header, render_suite_footer, render_main_promotional_banner

st.set_page_config(
    page_title="DeveloperOS - Cryptography Suite",
    page_icon="🔒",
    layout="wide",
)


def main():
    render_suite_header(
        title="Multi-Algorithm Hash & HMAC Generator",
        description="Compute cryptographic message digests (SHA-256, SHA-512, MD5) and HMAC signatures with zero server-side logging.",
    )

    data_input = st.text_area(
        "Input String to Hash:",
        value="DeveloperOS-Tools-Secure-2026",
        height=100,
    )

    use_hmac = st.checkbox("Compute HMAC Signature")
    hmac_key = None
    if use_hmac:
        hmac_key = st.text_input("HMAC Secret Key:", type="password", value="secret_passphrase")

    if data_input:
        results = compute_hashes(data_input, hmac_key=hmac_key)

        st.subheader("Cryptographic Digests")
        st.text_input("SHA-256", value=results["sha256"], disabled=True)
        st.text_input("SHA-512", value=results["sha512"], disabled=True)
        st.text_input("MD5 (Legacy Checksum)", value=results["md5"], disabled=True)

        if results["hmac_sha256"]:
            st.text_input("HMAC-SHA256", value=results["hmac_sha256"], disabled=True)

    render_main_promotional_banner()
    render_suite_footer()


if __name__ == "__main__":
    main()
