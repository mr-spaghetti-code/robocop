import streamlit as st

st.set_page_config(page_title="Configure", page_icon="🧩")

st.markdown("# Configure")

st.write(
    """Let's get the boring stuff out of the way. Configure your API keys below."""
)

status = st.info("You have not submitted any API keys yet.", icon="ℹ️")

openai_api_key = st.text_input(label="Enter your OpenAI API key.")

activeloop_api_key = st.text_input(label="Enter your Activeloop API key.")

anthropic_api_key = st.text_input(label="Enter your Anthropic API key.")


if "openai_api_key" not in st.session_state:
    st.session_state["openai_api_key"] = ''

if "activeloop_api_key" not in st.session_state:
    st.session_state["activeloop_api_key"] = ''

if "anthropic_api_key" not in st.session_state:
    st.session_state["anthropic_api_key"] = ''

if "settings_override" not in st.session_state:
    st.session_state["settings_override"] = False

if st.button("Override"):
    if not openai_api_key.startswith('sk-'):
        st.warning('Please enter your OpenAI API key. It starts with "sk-..."', icon='⚠')
    if openai_api_key.startswith('sk-') and activeloop_api_key != "":
        st.session_state["openai_api_key"] = openai_api_key
        st.session_state["activeloop_api_key"] = activeloop_api_key
        st.session_state["anthropic_api_key"] = anthropic_api_key
        st.session_state["settnigs_override"] = True
        status.success("Done!")
        st.balloons()

