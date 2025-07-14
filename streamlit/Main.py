
import streamlit as st
import requests
import json
import re
from io import BytesIO


def get_chat_response(db_uri, data_example, mask_data):
    url = 'http://fastapi:8080/get_node_in_english'
    with requests.post(url,
                       stream=True,
                       data={'db_uri': db_uri,
                             'data_example': data_example,
                             'mask_data': mask_data}) as response:
        for chunk in response.iter_content(chunk_size=1024):
            if chunk:
                parsed_chunk = str(chunk, encoding="utf-8")
                yield parsed_chunk


with st.form("user_form"):
    db_uri = st.text_input(
        label='db_uri',
        value='postgresql://postgres:postgres@postgres:5432/postgres')
    data_example = st.toggle('Add the data example?', value=False)
    mask_data = st.toggle('Mask the data?', value=False)
    submitted = st.form_submit_button("Get Database Metadata")

if submitted:
    with st.empty():
        db_metadata = st.write_stream(get_chat_response(
            db_uri,
            data_example,
            mask_data))
        st.write('')
    st.download_button('download_file',
                       data=db_metadata,
                       file_name='db_summary.txt')
    st.write(db_metadata)
