import os
import streamlit as st
import tiktoken

from langchain.chat_models import ChatOpenAI
from langchain.chains import ConversationalRetrievalChain
from langchain.embeddings.openai import OpenAIEmbeddings
from langchain.prompts import (
    ChatPromptTemplate,
    PromptTemplate,
    SystemMessagePromptTemplate,
    AIMessagePromptTemplate,
    HumanMessagePromptTemplate,
)
from langchain.vectorstores import DeepLake
from streamlit_chat import message


st.set_page_config(page_title="Q&A", page_icon="🤖")

st.markdown("# Q&A")
st.sidebar.header("Q&A")

st.write(
    """Now that the code has been processed, you can ask it questions. Load the embeddings then chat with Robocop."""
)

dataset_name = st.text_input(
    label="Dataset name"
)


if "openai_api_key" not in st.session_state:
    st.session_state["openai_api_key"] = ''

if "activeloop_api_key" not in st.session_state:
    st.session_state["activeloop_api_key"] = ''

if st.session_state["activeloop_api_key"] == '' or st.session_state["openai_api_key"] == '':
    status = st.info("You have not submitted any API keys yet. Go to the Configure page first.", icon="ℹ️")
else:
    pass


os.environ['OPENAI_API_KEY'] = st.session_state["openai_api_key"]
os.environ['ACTIVELOOP_TOKEN'] = st.session_state["activeloop_api_key"]

if "generated" not in st.session_state:
    st.session_state["generated"] = ["Hi, I'm Robocop. How may I help you?"]

if "past" not in st.session_state:
    st.session_state["past"] = ["Hi!"]

if "chat_history" not in st.session_state:
    st.session_state["chat_history"] = [("Hi","Hi, I'm Robocop. How may I help you?")]


template = """You are Robocop. Robocop is an expert in identifying security vulnerabilities in smart contracts and blockchain-related codebases. 

Robocop is a technical assistant that provides sophisticated and helpful answer. It stricly avoids giving false or misleading information, and it caveats when it is not entirely sure about the right answer.

Robocop is trained to analyze all logic with an "attacker" mindset, considering edge cases and extremes. It does not focus only on normal use cases. It reviews code line-by-line in detail, not just at a higher level. It does not assume any logic is fool proof.

Whenever it finds a vulnerability, Robocop provides a detailed explanation of the vulnerability, a proof of concept of how it might be exploited, and recommended steps to mitigate th risk.

Use the following pieces of context to answer the users question.
If you don't know the answer, just say that you don't know, don't try to make up an answer.
----------------
{context}
"""

system_message_prompt = SystemMessagePromptTemplate.from_template(template)

with st.expander("Advanced settings"):
    distance_metric = st.text_input(
        label="How to measure distance: (L2, L1, max, cos, dot)",
        value="cos"
    )
    model_option = st.selectbox(
        "What model would you like to use?",
        ('gpt-3.5-turbo','gpt-4')
    )
    temperature = st.text_input(
        label="Set temperature: 0 (deterministic) to 1 (more random).",
        value="0"
    )
    max_tokens = st.text_input(
        label="Max tokens in the response. (Default: 1000)",
        value="2000"
    )
    k = st.text_input(
        label="Number of results to return (Default: 10)",
        value="10"
    )
    k_for_mrr = st.text_input(
        label="Number of Documents to fetch to pass to MMR algorithm (Default: 100)",
        value="100"
    )
    maximal_marginal_relevance = st.checkbox(
        label="(Default: True)",
        value=True
    )

if st.button("Load embeddings"):
    status = st.info(f'Loading embeddings for {dataset_name}', icon="ℹ️")
    embeddings = OpenAIEmbeddings(disallowed_special=())
    dataset_path = f'hub://mrspaghetticode/{dataset_name}'
    print(f"Loading embeddings from {dataset_name}")
    try:
        db = DeepLake(dataset_path=dataset_path, read_only=True, embedding_function=embeddings)
        retriever = db.as_retriever()
        # Settings
        retriever.search_kwargs['distance_metric'] = distance_metric
        retriever.search_kwargs['k'] = int(k)
        retriever.search_kwargs['maximal_marginal_relevance'] = maximal_marginal_relevance
        retriever.search_kwargs['fetch_k'] = int(k_for_mrr)

        if "retriever" not in st.session_state:
            st.session_state["retriever"] = retriever
        print("Reset embeddings")
        print(st.session_state["retriever"])
        status.success(f"Embeddings loaded from {dataset_path}")
        st.session_state["generated"] = ["Hi, I'm Robocop. How may I help you?"]
        st.session_state["chat_history"] = [("Hi","Hi, I'm Robocop. How may I help you?")]
        st.session_state["past"] = ["Hi!"]
    except:
        status.warning("Could not load embeddings.")

def num_tokens_from_string(string: str, encoding_name: str) -> int:
    """Returns the number of tokens in a text string."""
    encoding = tiktoken.get_encoding(encoding_name)
    num_tokens = len(encoding.encode(string))
    return num_tokens

def generate_response(prompt, chat_history):
    # maybe use a different chain that includes model retriever, memory)
    # https://python.langchain.com/en/latest/modules/indexes/getting_started.html
    # https://github.com/hwchase17/langchain/discussions/3115

    model = ChatOpenAI(
        model_name=model_option, 
        temperature=float(temperature),
        max_tokens=max_tokens)
    print(model)
    qa = ConversationalRetrievalChain.from_llm(model,retriever=st.session_state["retriever"] )

    # This is a hack to modify the System prompt.
    qa.combine_docs_chain.llm_chain.prompt.messages[0] = system_message_prompt

    print(prompt)
    print(qa)
    # qa.combine_documents_chain.verbose = True
    # qa.verbose = True
    # qa.combine_docs_chain.verbose = True
    qa.combine_docs_chain.llm_chain.verbose = True
    print("***** Chat History *****")
    print(chat_history)
    response = qa.run(
        {"question": prompt,
        "chat_history": chat_history
        }
    )
    return response

def generate_first_response():
    with st.spinner('Loading Robocop...'):
        first_prompt = "Please provide an overview of the codebase along with some potential areas to examine for vulnerabilities."
        print(st.session_state["chat_history"])
        first_response = generate_response(first_prompt, st.session_state["chat_history"])
        st.session_state.past.append(first_prompt)
        st.session_state.generated.append(first_response)
        st.session_state.chat_history.append((first_prompt,first_response))

if st.button("🚨 Start 🚨"):
    generate_first_response()

st.header("Talk to Robocop")

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
            message(st.session_state['past'][i], is_user=True, key=str(i) + '_user', avatar_style="initials", seed="jc")
            message(st.session_state["generated"][i], key=str(i), avatar_style="bottts")