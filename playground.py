#!/usr/bin/env python
# coding: utf-8

# In[205]:


# from IPython.core.interactiveshell import InteractiveShell
# InteractiveShell.ast_node_interactivity = "all"


# In[206]:


# %pip install streamlit
# %pip install face_recognition


# In[224]:


import streamlit as st
import numpy as np
from datetime import datetime
import pickle 
from os.path import exists, getmtime
import binascii


# In[208]:


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
    


# In[209]:


# get_keys('ISHAN')


# In[210]:


test_set = """
SHANK///////-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr6d4GS3edNizrr7vywRS\n3PVIRV21OUmImHQgcLvEX8AeF4+puarPbsDs47DywYIk/D2GvFzW2m3s/h9VqGRh\nrsNl0NmUOuQ2VOHyb33xqayyNqbxqMcINBHVIxDp0QCUe5e5wF8T+8PQTePU9Ev0\n78lSsFWEYaTI7DXuzp2qSlC+y7+YC/SSVKCqahi93XDKjNhNBOuC7SweEXYjJdGT\nEJLomxa7k75WmyEpkSk7sWoD46gmSpdGxhk2WTV8Tp0MREjualc4yWFXMuaGTZv2\nqvvpcJL2GjvWHepqSXq6b0LntrVVWpc+DnCVPNfduxtepI91bzzS70N9D0g5MVxS\niQIDAQAB\n-----END PUBLIC KEY-----

ISHAN///////-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuOmpHDGz6Vf+Bmq0AuAl\nc9wnAlRfHEBawGG2U6hoZHqgHaRGbEGSJCAPuhTpJilywjp4dY1+qh6//v44hauR\nD/yKqVzHh5QDeSPlg+h68t1q3DAr++TsfnkU/CqmChTXRqSh/GawtwUDNVsqj6nW\nR9UM2EpD/yrqsdX8/pykM+npPM0/Rn+gb+9VyPk7JdzeqImeNU66Q5bSz7WHwPkm\n8NxPipLJVaH2Ud72NxV572RxidgHLlZHhedyZZwLl8bVwrcBghv1Y7O45gvVBvBs\nxspjEJEOlU6X6BYzIU+F1Jc3Nft1o6mQNko7Oe2Cwq/LjAydqlfDUbp4ObeEaagq\npQIDAQAB\n-----END PUBLIC KEY-----
"""


# In[211]:


test_key = """
ISHAN///////-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuOmpHDGz6Vf+Bmq0AuAl\nc9wnAlRfHEBawGG2U6hoZHqgHaRGbEGSJCAPuhTpJilywjp4dY1+qh6//v44hauR\nD/yKqVzHh5QDeSPlg+h68t1q3DAr++TsfnkU/CqmChTXRqSh/GawtwUDNVsqj6nW\nR9UM2EpD/yrqsdX8/pykM+npPM0/Rn+gb+9VyPk7JdzeqImeNU66Q5bSz7WHwPkm\n8NxPipLJVaH2Ud72NxV572RxidgHLlZHhedyZZwLl8bVwrcBghv1Y7O45gvVBvBs\nxspjEJEOlU6X6BYzIU+F1Jc3Nft1o6mQNko7Oe2Cwq/LjAydqlfDUbp4ObeEaagq\npQIDAQAB\n-----END PUBLIC KEY-----
"""


# In[212]:


def generate_santas(public_keys=test_set):
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


# In[234]:


encrypted_santas = """0baa6cc49f32ffd5948a81139a5fbf12dc34765af7af606d368518511d95e5f3733a2b40419825b45922607e546d410ae72d5bad59ad5dec97a1b61145c1db54edb104723c0f72a5e900ea15ac3b05b2654b2be5a4685ddef570a8b9fa9c572fc38385a0b95a532366d7f859fe5e48fac462cc7fb918b68343241d18d6cdf4b696c6b4cce4083147b8d1138dbb33bf60d9e55025e0f60ea70efcec04d054344d1f4331d3715a022e9ab37a91d5348ee527ba0d83e76a5c6b1d86b51561714bd4f3bae2b6e73e5a902508b004b345063c300e80488540019e1a024a0373b0fe78fc0d744c08ec1064db469b46cb9d5198d8783028d8c02ad525dec0b5618d156f"""


# In[235]:


private_key_str = """
CHELLO///////-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCu76OuAqZRKqBH
NeMEI8vZE7IIFhvDGGNBN8DaoUXZnfWCdPubXysZpR+/69/fb8E4a8XB9yqkmCVI
scIBVV9cG/TR7hDur3bEWBoV4G9ragdcQ9HkGHC2nA4u5aVd+VcnB/8edGdmyZh5
grUrFQVvBdYf9T604ybTBTqP6bhjelINi0RWQAW5eG/P9J5pLQ/x9DjRbDtNQXRh
7VSqey+8WE09B98Wbua0ktIZZKnjuhiffOp0a7WQtkUsbzshib+1L1wzTNFJaLqD
rGnpV0vvJumTjgGs0gVp5WiniOp+9XElnOEOs8JqH8C3lOXeIOmgcUJnvXwA9+ZJ
4cMYSxN1AgMBAAECggEAB73WqEF5Qz/H6obVtk3wPDnNJ+L0lRBr+guh1vsKmIwP
PJf5N4HBakferRNe66gqLJlGXeRWiISsJ7ioHX998hlRnwWyTaHJt3wvoVa2j5IY
Y8qji/zR5h7nWMd0Z0F8zB8kOOCNX+TdgMkaQ98RB74CIRVtEju4MN/7HLnK3WoO
Rk5iVbFDp1QaJJYSvhwahs5tSAVzJla3RQRHhCUwuI4kR4dtN5zHMrNgHhO07Q9/
/chaZ4nSs2y8W7Y3wzg8jpH41dOdskiSPGiJ+zUDoTl48BGN76QQLcdSYeib+IA+
xB3Pl5UFtUyFqSbQyodqZZE2grsqBiIRx2PHn7QkwQKBgQDsGrdnPEa2P97jAbAn
1jr1xX5jZu6kXbua40ooM9amBa1uL1EK38Onawwe12pKwELIuQD6bBhGh5xezVf0
vwQdpYNsKNAH5aOVermbObtk1RBFVfRRMoAhGxCULOW9ZoUqUpaI1XdvWhK0xKDJ
KVCr9348hJQ7L4sbqdSCIl/DwQKBgQC9rWP+SJfD+xxjXoXXRx1iwpvTTVd29QHh
BWWJl9XeoMRZ7hLqRvRwNjYEW77sNjUg317FQQpN72YM57k0j2gPkzX5uV+LuJ3M
IOk9cN9rl/MwAoFko11cTO78wM+31+rhN7tola/A80ygHTEnmV2nNU7nQ2FTPWm1
uzYN9xCstQKBgQDDUqLRc+sn0JUKhZX+jts+AYE6qKfaMHUIgOoTcjcsJ9w/IEPS
VCWfdg6T4S/c4UselPZ7NTur9Xpmb0hJgFDeWdPsgaMANXjsK5grE0q08xK/2YkC
N14KhUJk4vO4iXy285X3Y2moJAL/qv89C8HiUiAL3r5mbEGPxCK6+cbxwQKBgQCm
aqa8x7xAOuWhWaFcTAzARbaqIcWHnVdUsoNvwUPn3G3p6TO3USHOAgJKuKQ+YyEi
AlkIABSmZFDJKdYZA2ltoN9OhxIJaKUqIAYD3jBoGh1IFiqovZyACw/zuseEqXBu
wZMwI4TcaZrlMDecYrcEqYTc6wVNHyjMRcEbZ5W9sQKBgBXjqj3lSD/Asmak/iAZ
2bQVa0qsEwmLh2BVo/G3kljdf1KchNt383J8NaOCf/BHhVdbC+T6HyeV600aVNkB
JfbyfiYa1rAxLfh0zBfSOyMIZW/+K+H+a+d23bh3mte1fddr+5VHQ39KX/1BcA4x
nLNFJfms6QINVutXT2Fl1XpJ
-----END PRIVATE KEY-----
"""


# In[236]:


# binascii.unhexlify(encrypted_santas)


# In[237]:


# print("Ciphertext length:", len(binascii.unhexlify(encrypted_santas)))
# print("Key size:", private_key.key_size // 8)


# In[239]:


# private_key = serialization.load_pem_private_key(
#         private_key_str.encode(),
#         password=None,
#         backend=None
#     )

# santa = private_key.decrypt(
#     binascii.unhexlify(encrypted_santas),
#     padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
#         algorithm=hashes.SHA256(),
#         label=None
#         )
# )
# santa


# In[217]:


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
    print(encrypted_santas)
    encrypted_santas = encrypted_santas.split("\n\n")
    print(encrypted_santas)

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


# In[218]:


# str(encrypted_santas)


# In[219]:


st.set_page_config(
    page_title="Crypto Santa", 
    page_icon="🎅", 
    layout="centered", 
    initial_sidebar_state="collapsed", 
    menu_items=None
    )

st.title("Crypto Santa")


# In[220]:


tab_keys = ["Generate Your Keys", "Assign all Santas", "Find your Santa"]
tabs = st.tabs(tab_keys)   


# In[221]:


with tabs[0]:
    st.title(tab_keys[0])
    
    name = st.text_input('Name')
    name = name.upper()
    if name != '':
        private_key, public_key = get_keys(name)

        
        st.write('Your private key is: ')
        st.code(private_key)
        st.write('Your public key is: ')
        st.code(public_key)

    


# In[222]:


with tabs[1]:
    st.title(tab_keys[1])
    with st.form("my_form"):
        public_keys = st.text_area('Public Keys, seprated by new line')

        # Every form must have a submit button.
        submitted = st.form_submit_button("Submit")
        if submitted:
            encrypted_santas = generate_santas(public_keys)
            display_codes = ""
            for santa in encrypted_santas:
                display_codes = display_codes + santa.decode('ascii') + "\n\n"
            st.code(display_codes)


# In[223]:


with tabs[2]:
    st.title(tab_keys[2])
    with st.form("my_form_2"):
        private_key_str = st.text_area('Your Private Key')
        encrypted_santas = st.text_area('Encrypted Santas')

        # Every form must have a submit button.
        submitted = st.form_submit_button("Submit")
        if submitted:
            santas = find_your_santa(private_key_str, encrypted_santas)
            # display_codes = ""
            # for santa in santas:
            #     # dec = str(santa)
            #     # print(dec)
            #     display_codes = display_codes + santa.decode('utf-8') + "\n\n"
            st.code(santas)

