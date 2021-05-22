FROM python:3.9-slim

# working folder
RUN mkdir /build
WORKDIR /build

# install dependencies (highly cacheable)
RUN apk update \
    && apk add --no-cache zip

# add source code
COPY lambda_function.py /build/lambda_function.py

# zip entire context and stream output
RUN zip -r /build/dist.zip . > /dev/null
CMD ["cat", "/build/dist.zip"]
