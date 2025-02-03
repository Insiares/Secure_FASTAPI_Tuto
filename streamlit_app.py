import streamlit as st
import requests

API_URL = "http://localhost:8000"

st.title("OAuth2 Demo")


if 'access_token' not in st.session_state:
    st.session_state['access_token'] = '' # I set it to an empty string for testing the no token case, but this is bad practice 

if st.session_state['access_token'] != '':
    st.write("You are logged in.")
else:
    st.write("You are NOT logged")

access_token = st.session_state['access_token']

with st.form("login_form"):
    username = st.text_input("Username", value="user")
    password = st.text_input("Password", type="password", value="pass")
    submitted = st.form_submit_button("Login")

if submitted:
    token_url = f"{API_URL}/token"
    data = {
        "username": username,
        "password": password,
    }
    response = requests.post(token_url, data=data)
    if response.status_code == 200:
        token_data = response.json()
        st.success("Login successful!")
        access_token = token_data.get("access_token")
        st.write("Access Token:", access_token)
        # Token in session_state for persistence between reruns
        st.session_state['access_token'] = access_token
    else:
        st.error("Login failed. Please check your credentials.")

# Retrieve secure data
if st.button("Call secured route with token headers"):
    # The header is where the magic is hapenning
    headers = {"Authorization": f"Bearer {access_token}"}
    secure_response = requests.get(f"{API_URL}/secure-route", headers=headers)
    if secure_response.status_code == 200:
        secure_data = secure_response.json()
        st.write("Secure Data:", secure_data)
    else:
        st.error("Failed to retrieve secure data.")

# Call the open routes
if st.button("Call not-secure route"):
    not_secure_response = requests.get(f"{API_URL}/not-secure-route")
    if not_secure_response.status_code == 200:
        not_secure_data = not_secure_response.json()
        st.write("Not Secure Data:", not_secure_data)
    else:
        st.error("Failed to retrieve not-secure data.")

# To call the secure route by omitting the bearer token
if st.button("Call secure route without headers"):
    # no bearer token, no data
    secure_response = requests.get(f"{API_URL}/secure-route")
    if secure_response.status_code == 200:
        secure_data = secure_response.json()
        st.write("Secure Data:", secure_data)
    else:
        st.error("Failed to retrieve secure data.")
