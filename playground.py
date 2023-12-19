#!/usr/bin/env python
# coding: utf-8

# In[ ]:


# from IPython.core.interactiveshell import InteractiveShell
# InteractiveShell.ast_node_interactivity = "all"


# In[ ]:


# %pip install streamlit
# %pip install face_recognition


# In[ ]:


import streamlit as st
import numpy as np
from datetime import datetime
import pickle 
from os.path import exists, getmtime
import binascii


# In[ ]:


from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def get_keys(name):

    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Generate public key
    public_key = private_key.public_key()

    # Serialize private key
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # print(pem.decode())

    private_key_str = name + "///////" + pem.decode()

    # Serialize public key
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # print(pem.decode())

    public_key_str = name + "///////" + pem.decode()

    return private_key_str, public_key_str
    


# In[ ]:


def generate_santas(public_keys):
    users = public_keys.split("\n\n")
    user_key = {user.split("///////")[0]:user.split("///////")[1] for user in users}
    # print(user_key)

    # Pick the user first in ascending order of name
    first_user = sorted(user_key.keys())[0]

    # Use that user as the seed for the random number generator
    np.random.seed(int(first_user, 36)%2**31)

    # Generate random order
    names = list(user_key.keys())
    np.random.shuffle(names)

    # Generate santas
    santas = {}
    for i in range(len(names)):
        santas[names[i]] = names[(i+1)%len(names)]

    # Encrypt santas
    encrypted_santas = []
    for name in names:

        # Get public key
        public_key_str = user_key[name]

        public_key = serialization.load_pem_public_key(
            public_key_str.encode(),
            backend=None
        )

        print(santas[name])

        # Encrypt the santa
        encrypted_santa = public_key.encrypt(
            santas[name].encode(),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                )
        )

        # Add to list
        
        encrypted_santas.append(binascii.hexlify(encrypted_santa))


    return encrypted_santas
# generate_santas(public_keys=test_set)


# In[ ]:


def find_your_santa(private_key_str, encrypted_santas):
    # Get private key
    private_key_str = private_key_str.split("///////")[1]
    private_key = serialization.load_pem_private_key(
        private_key_str.encode(),
        password=None,
        backend=None
    )

    # Decrypt santas
    santas = [] 
    encrypted_santas = encrypted_santas.split("\n\n")

    for encrypted_santa in encrypted_santas:
            
        try:
        # Decrypt the santa
            santa = private_key.decrypt(
                binascii.unhexlify(encrypted_santa),
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                    )
            )
            santas.append(santa.decode())
        except:
            pass
    
            # Add to list
            

    return santas

# find_your_santa(private_key_str, encrypted_santas)


# In[ ]:


st.set_page_config(
    page_title="Crypto Santa", 
    page_icon="🎅", 
    layout="centered", 
    initial_sidebar_state="collapsed", 
    menu_items=None
    )


# In[ ]:


st.title("⛄ Crypto ❄️ Santa 🎄")


# In[ ]:


st.write("Secret Santa has a super neat feature: when played with chits of paper, the information of the total state of game - the overall Santa mapping - is never available to anyone.")
st.write("Let's overly complicate this.")
st.write("")
st.markdown("**...but also, treat this as a theoretical exercise in secure multiparty computation**")


# In[ ]:


tab_keys = ["[1]: What's your Keys", "[2]: Assign all Santas", "[3]: Who you gifting", "[0]: About"]
tabs = st.tabs(tab_keys)   


# In[ ]:


with tabs[0]:
    st.subheader(tab_keys[0])
    
    with st.form("aaa"):
        name = st.text_input('Name')
        name = name.upper()
        submitted = st.form_submit_button(label='Submit')
        if submitted:
            private_key, public_key = get_keys(name)

            st.write('Your private key is: ')
            st.code(private_key)
            st.write('Your public key is: ')
            st.code(public_key)

    


# In[ ]:


with tabs[1]:
    st.subheader(tab_keys[1])
    with st.form("bbb"):
        public_keys = st.text_area('Public Keys, seprated by new line')

        # Every form must have a submit button.
        submitted = st.form_submit_button("Submit")
        if submitted:
            encrypted_santas = generate_santas(public_keys)
            display_codes = ""
            for santa in encrypted_santas:
                display_codes = display_codes + santa.decode('ascii') + "\n\n"
            st.code(display_codes)


# In[ ]:


with tabs[2]:
    st.subheader(tab_keys[2])
    with st.form("ccc"):
        private_key_str = st.text_area('Your Private Key')
        encrypted_santas = st.text_area('Encrypted Santas')

        # Every form must have a submit button.
        submitted = st.form_submit_button("Submit")
        if submitted:
            santas = find_your_santa(private_key_str, encrypted_santas)
            st.code(santas)


# In[ ]:


with tabs[3]:
    st.subheader(tab_keys[3])
    st.write("""
    This is an overly complicated rendition of the meat-space tradition of Secret Santa.
    It uses RSA encryption to allow you to assign secret santas to a group of people without
    anyone knowing who anyone else is the secret santa for.
             
    The first step is to generate your keys. You can do this by entering your name in the box
    and clicking submit. This will generate your public and private keys. You should share your
    public key with the person who is assigning the secret santas. You should keep your private key
    secret.
    
    The second step is to assign all the secret santas. The person who is assigning the secret santas should
    collect all the public keys and enter them into the box. Clicking submit will generate a list of encrypted
    santas. Each santa should be sent to the person who it is assigned to.
    
    The third step is to find out who you are the santa for. You should enter your private key and all the
    encrypted santas you have received. Clicking submit will decrypt the santas and tell you who you are the
    santa for.  
    """)


# In[ ]:


st.markdown("yours in complication, [🐙](https://knhash.in)")

