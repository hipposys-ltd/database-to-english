from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from typing import Annotated
from server.tr_db_to_english import PostgreSQLMetadataExtractor
from fastapi.responses import StreamingResponse
import json
import io
import docx
import PyPDF2


app = FastAPI()


@app.get("/")
def read_root():
    return {"message": "Hello, FastAPI!"}


@app.post("/get_node_in_english")
async def get_node_in_english(db_uri: Annotated[str, Form()],
                              data_example: Annotated[bool, Form()],
                              mask_data: Annotated[bool, Form()]):
    return StreamingResponse(PostgreSQLMetadataExtractor.extract_metadata(
        postgres_uri=db_uri,  # "postgresql://user:pass@host:port/dbname"
        include_sample_data=data_example,
        mask_sample_data=mask_data,
        return_as_string=True,
        markdown=True,
        stream_results=True
    ), media_type='text/plain')
