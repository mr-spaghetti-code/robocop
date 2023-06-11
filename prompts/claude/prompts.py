import prompts.examples
import anthropic
from langchain import PromptTemplate

human_prefix = anthropic.HUMAN_PROMPT
assistant_prefix = anthropic.AI_PROMPT

def generateExamples(examples):
    resp = ""
    for example in examples:
        vulnerable_code = example["flawed"]
        fixed_code = example["fixed"]
        string = f"\nVulnerable code:\n```solidity\n{vulnerable_code}```\nFixed code:\n```solidity\n{fixed_code}\n```"
        resp += string
    return resp

VULNERABILITIES = {
    "reentrancy" : {
        "category" : "L1",
        "description": "One of the major dangers of calling external contracts is that they can take over the control flow. In the reentrancy attack (a.k.a. recursive call attack), a malicious contract calls back into the calling contract before the first invocation of the function is finished. This may cause the different invocations of the function to interact in undesirable ways.",
        "examples" : generateExamples(prompts.examples.REENTRANCY_EXAMPLES)
    },
    "overflow_underflow" : {
        "category" : "L7",
        "description" : "An overflow/underflow happens when an arithmetic operation reaches the maximum or minimum size of a type. For instance if a number is stored in the uint8 type, it means that the number is stored in a 8 bits unsigned number ranging from 0 to 2^8-1. In computer programming, an integer overflow occurs when an arithmetic operation attempts to create a numeric value that is outside of the range that can be represented with a given number of bits – either larger than the maximum or lower than the minimum representable value.",
        "examples" : generateExamples(prompts.examples.OVERFLOW_UNDERFLOW_EXAMPLES)
    },
    "gas_limit_exceeded" : {
        "category" : "L4",
        "description" : "A gas limit vulnerability is when a Solidity contract consumes so much gas during a function call that it exceeds the block gas limit, causing the transaction to revert. gas limit vulnerabilities allow attackers to manipulate and corrupt smart contract state and logic without paying the full gas costs of their actions",
        "examples" : generateExamples(prompts.examples.GAS_EXCEEDED_EXAMPLES)
    },
    "tx_origin" : {
        "category" : "LB",
        "description" : "tx.origin is a global variable in Solidity which returns the address of the account that sent the transaction. Using the variable for authorization could make a contract vulnerable if an authorized account calls into a malicious contract. A call could be made to the vulnerable contract that passes the authorization check since tx.origin returns the original sender of the transaction which in this case is the authorized account.",
        "examples" : generateExamples(prompts.examples.TX_ORIGIN_EXAMPLES)
    },
    "uninitialized_variable" : {
            "category" : "L3",
            "description" : "Uninitialized variable vulnerabilities in Solidity allow attackers to shadow and manipulate contract variables by declaring their own local variables of the same name. Because uninitialized variables have undefined values, attackers can control what values the contract variables take on by initializing their own local shadows.",
            "examples" : generateExamples(prompts.examples.UNINITIALIZED_VARIABLES)
    }
}

CONTEXT_TEMPLATE_PROVIDE_SUMMARY = """Human: Summarize the code below (enclosed in the <code> tags) and explain in bullet points what it does. Write the response in markdown format starting with `## Summary`

Code to be summarized:
<code>
{code}
</code>

Assistant:
"""


CONTEXT_TEMPLATE_WITH_SUMMARY = """Human: You are Robocop. Robocop is an expert in identifying security vulnerabilities in smart contracts and blockchain-related codebases. 

Robocop is a technical assistant that provides detailed, structured, and helpful answers. 

Here are some important rules for Robocop:
- Robocop is trained to analyze all logic with an "attacker" mindset, considering edge cases and extremes. 
- It does not focus only on normal use cases.
- It reviews code line-by-line in detail, not just at a higher level.
- It does not assume any logic is fool proof.
- If it does not know the answer, it simply says "I don't know". It does not make up an answer.

Summary of {smart_contract_name} <summary></summary> XML tags:
<summary>
{summary}
</summary>

The code for you to audit:
<code>
{code}
</code>

Your task:
<task>{task}</task>

Assistant:
"""

CONTEXT_TEMPLATE_TASK = """
Analyze the code for {type} and find ALL vulnerabilities, no matter how small.

Description of vulnerability: {description}

Examples:
<examples>
{examples}
</examples>

Important: There are likely some vulnerabilities in the code provided. Consider each function independently and carefully. 

Generate an exhaustive audit report containing all the vulnerabilities you identify and enclose it in <report></report> tags.

Each vulnerability should follow the structure in <report></report>:
<report>
## Description:

<description>Description of the vulnerability</description>

## Impact:

<impact>Description the impact of this vulnerability. Provide a comprehensive assessment with code examples.</impact>

## Mitigation:

<mitigation>Explanation why this is a vulnerability and how to mitigate it. Provide a fix in the code. Use backticks for any code blocks.</mitigation>
</report>

Ensure that your report is accurate and doesn’t contain any information not directly supported by the code provided.
"""



USER_TEMPLATE_PROVIDE_SUMMARY = PromptTemplate(
    input_variables=[
        "code"
        ], 
    template=CONTEXT_TEMPLATE_PROVIDE_SUMMARY)

USER_TEMPLATE_TASK = PromptTemplate(
    input_variables=[
        "type",
        "description",
        "examples"
        ], 
    template=CONTEXT_TEMPLATE_TASK)


USER_TEMPLATE_WITH_SUMMARY = PromptTemplate(
    input_variables=[
        "smart_contract_name",
        "summary",
        "code",
        "task"
        ], 
    template=CONTEXT_TEMPLATE_WITH_SUMMARY)
