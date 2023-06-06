import os
import streamlit as st

from langchain.chat_models import ChatOpenAI
from langchain.chains import ConversationalRetrievalChain
from langchain.embeddings.openai import OpenAIEmbeddings
from langchain.vectorstores import DeepLake
from streamlit_chat import message


st.set_page_config(page_title="Q&A", page_icon="🤖")

st.markdown("# Q&A")
st.sidebar.header("Q&A")

st.write(
    """Now that the code has been processed, you can ask it questions. Load the embeddings then click on "Chat"."""
)

github_url = st.text_input(
    label="Enter the URL of a _public_ GitHub repo"
)

os.environ['OPENAI_API_KEY'] = st.session_state["openai_api_key"]
os.environ['ACTIVELOOP_TOKEN'] = st.session_state["activeloop_api_key"]

if "generated" not in st.session_state:
    st.session_state["generated"] = ["Hi, I'm Robocop. How may I help you?"]

if "past" not in st.session_state:
    st.session_state["past"] = ["Hi!"]

if "chat_history" not in st.session_state:
    st.session_state["chat_history"] = [("Hi","Hi, I'm Robocop. How may I help you?")]




with st.expander("Advanced settings"):
    distance_metric = st.text_input(
        label="How to measure distance: (L2, L1, max, cos, dot)",
        value="cos"
    )
    model_option = st.selectbox(
        "What model would you like to use?",
        ('gpt-3.5-turbo','gpt-4')
    )

ready = False

if st.button("Load embeddings"):
    status = st.info(f'Loading embeddings for {github_url}', icon="ℹ️")
    embeddings = OpenAIEmbeddings(disallowed_special=())
    name = github_url.split("/")[-1]
    dataset_path = f'hub://mrspaghetticode/{name}'
    db = DeepLake(dataset_path=dataset_path, read_only=True, embedding_function=embeddings)

    retriever = db.as_retriever()
    retriever.search_kwargs['distance_metric'] = distance_metric
    if "retriever" not in st.session_state:
        st.session_state["retriever"] = retriever



# Layout of input/response containers
response_container = st.container()
input_container = st.container()

# User input
## Function for taking user provided prompt as input
def get_text():
    input_text = st.text_input("You: ", "", key="input")
    return input_text
## Applying the user input box
with input_container:
    user_input = get_text()


def generate_response(prompt, chat_history):
    model = ChatOpenAI(model_name=model_option)
    qa = ConversationalRetrievalChain.from_llm(model,retriever=st.session_state["retriever"] )
    response = qa.run(
        {"question": prompt,
        "chat_history": chat_history
        }
    )
    return response


## Conditional display of AI generated responses as a function of user provided prompts
with response_container:
    if user_input:
        with st.spinner('Processing...'):
            response = generate_response(user_input, st.session_state["chat_history"])
            st.session_state.past.append(user_input)
            st.session_state.generated.append(response)
            st.session_state.chat_history.append((user_input,response))
        

        
    if st.session_state['generated']:
        for i in range(len(st.session_state['generated'])):
            message(st.session_state['past'][i], is_user=True, key=str(i) + '_user')
            message(st.session_state["generated"][i], key=str(i))