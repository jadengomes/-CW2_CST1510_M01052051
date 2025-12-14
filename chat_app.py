import streamlit as st
from openai import OpenAI, RateLimitError


# Page configuration (MUST be first Streamlit call)

st.set_page_config(
    page_title="ChatGPT Lab",
    page_icon="💬"
)

st.title("💬 ChatGPT – Week 10 Lab")


# Initialize OpenAI client (API key from secrets)

client = OpenAI(api_key=st.secrets["OPENAI_API_KEY"])


# Initialize session state for chat history

if "messages" not in st.session_state:
    st.session_state.messages = []


# Display previous chat messages

for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])


# User input

prompt = st.chat_input("Type your message...")

if prompt:
    # Show user message
    with st.chat_message("user"):
        st.markdown(prompt)

    st.session_state.messages.append({
        "role": "user",
        "content": prompt
    })

 
    # Call OpenAI API with proper error handling
 
    with st.spinner("Thinking..."):
        try:
            response = client.chat.completions.create(
                model="gpt-4o",
                messages=st.session_state.messages
            )
            reply = response.choices[0].message.content

        except RateLimitError:
            reply = (
                "⚠️ **OpenAI API quota exceeded**\n\n"
                "The application is correctly integrated with the OpenAI API, "
                "but this account has no remaining credits.\n\n"
                "Please add billing credits on **platform.openai.com** to continue."
            )

        except Exception as e:
            reply = (
                "⚠️ **Unexpected error occurred**\n\n"
                f"{e}"
            )

    # Show assistant response
    with st.chat_message("assistant"):
        st.markdown(reply)

    st.session_state.messages.append({
        "role": "assistant",
        "content": reply
    })
