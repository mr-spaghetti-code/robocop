import anthropic
import json
import os
import tempfile

from prompts.claude import prompts
import streamlit as st

from streamlit.logger import get_logger
from langchain.chains import LLMChain
from langchain.chat_models import ChatAnthropic
from langchain.document_loaders import GitLoader
from langchain.llms import Anthropic


from langchain.prompts import (
    ChatPromptTemplate,
    PromptTemplate,
    SystemMessagePromptTemplate,
    AIMessagePromptTemplate,
    HumanMessagePromptTemplate,
)
from langchain.schema import (
    AIMessage,
    HumanMessage,
    SystemMessage
)

st.set_page_config(page_title="Report", page_icon="📖")

st.markdown(
    """This section pulls raw code directly from Github instead of finding relevant embeddings then generates a report.
    """
)

logger = get_logger(__name__)

SYSTEM_TEMPLATE_PERSONA = """You are Robocop. Robocop is an expert in identifying security vulnerabilities in smart contracts and blockchain-related codebases. 

Robocop is a technical assistant that provides detailed, structured, and helpful answers. 

Robocop is trained to analyze all logic with an "attacker" mindset, considering edge cases and extremes. 
It does not focus only on normal use cases.
It reviews code line-by-line in detail, not just at a higher level.
It does not assume any logic is fool proof.
"""

SYSTEM_TEMPLATE_INFO = """
--------
TASK:
{task}
--------
CODE TO AUDIT:
{code}
--------
"""

SYSTEM_TEMPLATE_SUMMARIZE = SYSTEM_TEMPLATE_PERSONA + SYSTEM_TEMPLATE_INFO
SYSTEM_TEMPLATE_TASK_SUMMARIZE = """You will summarize the code below and explain in bullet points what it does. Write the response in markdown format starting with `## Summary`"""
SYSTEM_TEMPLATE_TASK_OVERFLOW = """Audit the code provided to detect any integer overflows or underflows.

Description of vulnerability:
An overflow/underflow happens when an arithmetic operation reaches the maximum or minimum size of a type. For instance if a number is stored in the uint8 type, it means that the number is stored in a 8 bits unsigned number ranging from 0 to 2^8-1. In computer programming, an integer overflow occurs when an arithmetic operation attempts to create a numeric value that is outside of the range that can be represented with a given number of bits – either larger than the maximum or lower than the minimum representable value.

EXAMPLE 1:
Buggy code:
//Single transaction overflow

pragma solidity ^0.4.11;

contract IntegerOverflowMappingSym1 {
    mapping(uint256 => uint256) map;

    function init(uint256 k, uint256 v) public {
        map[k] -= v;
    }
}

Fixed:
//Single transaction overflow
//Safe version

pragma solidity ^0.4.16;

contract IntegerOverflowMappingSym1 {
    mapping(uint256 => uint256) map;

    function init(uint256 k, uint256 v) public {
        map[k] = sub(map[k], v);
    }

    //from SafeMath
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a);//SafeMath uses assert here
        return a - b;
    }
}

EXAMPLE 2:
Buggy code:
//Single transaction overflow
//Post-transaction effect: overflow escapes to publicly-readable storage

pragma solidity ^0.4.19;

contract IntegerOverflowMinimal {
    uint public count = 1;

    function run(uint256 input) public {
        count -= input;
    }
}

Fixed:
//Single transaction overflow
//Post-transaction effect: overflow escapes to publicly-readable storage
//Safe version

pragma solidity ^0.4.19;

contract IntegerOverflowMinimal {
    uint public count = 1;

    function run(uint256 input) public {
        count = sub(count,input);
    }

    //from SafeMath
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a);//SafeMath uses assert here
        return a - b;
    }
}
"""

SYSTEM_TEMPLATE_TASK_REENTRANCY = """Audit the code provided to detect any reentrancy vulnerabilities.

Description of vulnerability:
One of the major dangers of calling external contracts is that they can take over the control flow. In the reentrancy attack (a.k.a. recursive call attack), a malicious contract calls back into the calling contract before the first invocation of the function is finished. This may cause the different invocations of the function to interact in undesirable ways.

The best practices to avoid Reentrancy weaknesses are:

Make sure all internal state changes are performed before the call is executed. This is known as the Checks-Effects-Interactions pattern
Use a reentrancy lock (ie. OpenZeppelin's ReentrancyGuard.

EXAMPLE 1:
Buggy code:
pragma solidity ^0.5.0;

contract ModifierEntrancy {

  mapping (address => uint) public tokenBalance;
  string constant name = "Nu Token";
  Bank bank;
  
  constructor() public{
      bank = new Bank();
  }

  //If a contract has a zero balance and supports the token give them some token
  function airDrop() hasNoBalance supportsToken  public{
    tokenBalance[msg.sender] += 20;
  }
  
  //Checks that the contract responds the way we want
  modifier supportsToken() {
    require(keccak256(abi.encodePacked("Nu Token")) == bank.supportsToken());
    _;
  }
  
  //Checks that the caller has a zero balance
  modifier hasNoBalance {
      require(tokenBalance[msg.sender] == 0);
      _;
  }
}

contract Bank{

    function supportsToken() external returns(bytes32) {
        return keccak256(abi.encodePacked("Nu Token"));
    }

}

Fixed:
pragma solidity ^0.5.0;

contract ModifierEntrancy {
  mapping (address => uint) public tokenBalance;
  string constant name = "Nu Token";
  Bank bank;
  constructor() public{
      bank = new Bank();
  }

  //If a contract has a zero balance and supports the token give them some token
  function airDrop() supportsToken hasNoBalance  public{ // In the fixed version supportsToken comes before hasNoBalance
    tokenBalance[msg.sender] += 20;
  }

  //Checks that the contract responds the way we want
  modifier supportsToken() {
    require(keccak256(abi.encodePacked("Nu Token")) == bank.supportsToken());
    _;
  }
  //Checks that the caller has a zero balance
  modifier hasNoBalance {
      require(tokenBalance[msg.sender] == 0);
      _;
  }
}

contract Bank{

    function supportsToken() external returns(bytes32){
        return(keccak256(abi.encodePacked("Nu Token")));
    }
}

EXAMPLE 2:
Buggy code:
/*
 * @source: http://blockchain.unica.it/projects/ethereum-survey/attacks.html#simpledao
 */
pragma solidity 0.4.24;

contract SimpleDAO {
  mapping (address => uint) public credit;
    
  function donate(address to) payable public{
    credit[to] += msg.value;
  }
    
  function withdraw(uint amount) public{
    if (credit[msg.sender]>= amount) {
      require(msg.sender.call.value(amount)());
      credit[msg.sender]-=amount;
    }
  }  

  function queryCredit(address to) view public returns(uint){
    return credit[to];
  }
}

Fixed:
/*
 * @source: http://blockchain.unica.it/projects/ethereum-survey/attacks.html#simpledao
 */
pragma solidity 0.4.24;

contract SimpleDAO {
  mapping (address => uint) public credit;
    
  function donate(address to) payable public{
    credit[to] += msg.value;
  }
    
  function withdraw(uint amount) public {
    if (credit[msg.sender]>= amount) {
      credit[msg.sender]-=amount;
      require(msg.sender.call.value(amount)());
    }
  }  

  function queryCredit(address to) view public returns (uint){
    return credit[to];
  }
}
"""

SYSTEM_TEMPLATE_RESPONSE_STRUCTURE = """
For every vulnerability you identify, answer in the following structure using markdown:
----
## Description: 
[Description of the vulnerability]

## Impact: 
[Description the impact of this vulnerability. Provide a comprehensive assessment with code examples.]

## Explanation: 
[Explanation why this is a vulnerability and how to fix it]
-----
"""



if "anthropic_api_key" not in st.session_state:
    st.session_state["anthropic_api_key"] = ''

if "raw_code" not in st.session_state:
    st.session_state["raw_code"] = []

if "settings_override" not in st.session_state:
    st.session_state["settings_override"] = []

if "contract_names" not in st.session_state:
    st.session_state["contract_names"] = []

if "reports_to_generate" not in st.session_state:
    st.session_state["reports_to_generate"] = []

# if "vulnerabilities_to_find" not in st.session_state:
#     st.session_state["vulnerabilities_to_find"] = []


os.environ['ANTHROPIC_API_KEY'] = st.session_state["anthropic_api_key"] if st.session_state["settings_override"] else st.secrets.anthropic_api_key

st.markdown("# Report")

github_url = st.text_input(
    label="Enter the URL of a _public_ GitHub repo")

commit_branch = st.text_input(label="Enter the commit ID (optional) or branch (default:main",
    value="master or main or your commit ID")


def load_text(clone_url):
    # loader = GitLoader(repo_path="./juice-buyback/")
    loader = GitLoader(
        clone_url=clone_url,
        repo_path=tmpdirname,
        branch=commit_branch,
        file_filter=lambda file_path: file_path.endswith(".sol")
    )
    data = loader.load()
    st.session_state["raw_code"] = data
    return data

def filter_by_type(file_type):
    filtered_text = list(filter(lambda doc: (doc.metadata['file_type'] == file_type), st.session_state["raw_code"]))
    return filtered_text

def filter_by_name(name):
    filtered_text = list(filter(lambda doc: (doc.metadata['file_name'] == name), st.session_state["raw_code"]))
    return filtered_text

button = st.button("Analyze")

if button:
    status = st.info(f'Pulling from {github_url}', icon="ℹ️")
    with st.spinner('Processing...'):
        with tempfile.TemporaryDirectory() as tmpdirname:
            logger.info(f'Created temporary directory: {tmpdirname}')

            status.info("Loading data")

            texts = load_text(clone_url=github_url)

            status.info("Data loaded")

            logger.info("Data retrieved")

            contracts = filter_by_type(".sol")

            contract_names = [contract.metadata["file_name"] for contract in contracts]
            st.session_state["contract_names"] = contract_names


st.header("Contracts")

reports_to_generate = st.multiselect(
    "Pick the smart contracts you want to generate reports for.",
    st.session_state["contract_names"]
)

st.session_state["reports_to_generate"] = reports_to_generate

vulnerabilities_to_find = st.multiselect(
    "Pick the vulnerabilities to look for.",
    list(prompts.VULNERABILITIES.keys())
)

generated_reports = []

llm = Anthropic(
    temperature=0,
    max_tokens_to_sample=1024,
    verbose=True
)

output_txt = ""

if st.button("Generate Reports"):
    status = st.info(f'Generating reports', icon="ℹ️")
    output_txt += f"# Robocop Audit report Report for {github_url}\n"
    for report in st.session_state["reports_to_generate"]:
        st.info(f'Generating report for {report}', icon="ℹ️")
        summary = ''
        gen_report = {}
        gen_report[report] = {}
        gen_report[report]["file"] = report
        output_txt += f"## File Analyzed: {report}\n"
        with st.spinner('Retrieving code...'):
            code = filter_by_name(report)[0].page_content
            num_tokens = anthropic.count_tokens(code)
            gen_report['code'] = code
            gen_report['num_tokens_code'] = num_tokens
            logger.info(f"Processing code:\n{code}")
            status.info(f'Retrieved code for {report} - Processing {num_tokens} tokens.', icon="ℹ️")
        with st.spinner('Getting summary...'):
            chain = LLMChain(llm=llm, prompt=prompts.USER_TEMPLATE_PROVIDE_SUMMARY)
            response = chain.run({
                'code': code
                })
            summary = response
            logger.info(f"RESPONSE RECEIVED\n*********\n{response}")
            gen_report[report]['summary'] = response
            output_txt += response + "\n"
            st.write(response)
        for vulnerability in vulnerabilities_to_find:
            with st.spinner(f'Scanning for {vulnerability} bugs...'):
                formatted_task = prompts.USER_TEMPLATE_TASK.format(
                    type=vulnerability, 
                    description=prompts.VULNERABILITIES[vulnerability]["description"], 
                    examples=prompts.VULNERABILITIES[vulnerability]["description"])
                
                chain = LLMChain(llm=llm, prompt=prompts.USER_TEMPLATE_WITH_SUMMARY)
                response = chain.run({
                    "smart_contract_name": report,
                    "summary": summary,
                    "code": code,
                    "task": formatted_task
                    })
                logger.info(f"RESPONSE RECEIVED\n*********\n{response}")
                response = response.replace("<report>","").replace("</report>","").replace("<description>","").replace("</description>","").replace("<impact>","").replace("</impact>","").replace("<mitigation>","").replace("</mitigation>","")
                gen_report[report]['bugs'] = {
                    vulnerability : response.replace("<report>","").replace("</report>","")
                }
                output_txt += f"# Analysis results for {vulnerability} vulnerabilities \n\n"
                output_txt += response + "\n"
                st.write(f"# Analysis results for {vulnerability} vulnerabilities \n\n", response)
                generated_reports.append(gen_report)
    logger.info(generated_reports)
    status.success("Done!")
    st.balloons()

json_obj = json.dumps(generated_reports)
st.download_button(
    label="Download data as JSON",
    data=json_obj,
    file_name='report_findings.json',
    mime='application/json',
)
st.download_button(
    label="Download data as Text (markdown)",
    data=output_txt,
    file_name='report_findings.md',
    mime='text/plain',
)

