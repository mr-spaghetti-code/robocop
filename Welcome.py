import streamlit as st

st.set_page_config(
    page_title="Welcome",
    page_icon="🤖"
)

st.write("# Welcome to Robocop 🤖🚔")

st.markdown(
    """
    Robocop is an AI-powered tool for security researchers. It uses large language models (LLMs) to help identify and fix vulnerabilities in smart contracts.

    ### How does it work?
    Robocop slurps in all the target code then analyzes it for common vulnerabilities. There are 4 main pages:
    - 🧩 Configure: Add your API keys (Note: by default you don't have to unless you want to override them)
    - 🤖 Analyze: Compute embeddings for your code base.
    - 🗣️ Ask: Chat interactively with the code base. Robocop is there to answer any questions you have about the code you are analyzing.
    - 📖 Report: Generate a full report of the target base.

    **This is a prototype built by Joao Fiadeiro at Jump Crypto.**
    """
)

