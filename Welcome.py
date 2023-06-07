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
    First, go to "Load Data" and enter the URL of a public GitHub repo then click "Analyze". Robocop will download and process all the files in the repo.
    Next, you will be able to chat with an LLM (like ChatGPT) to identify potential vulnerabilities.
    """
)

