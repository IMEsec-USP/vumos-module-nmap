FROM python:3

# Install nmap
WORKDIR /
RUN git clone https://github.com/nmap/nmap.git
WORKDIR /nmap
RUN ./configure
RUN make
RUN make install

WORKDIR /
RUN rm -rf /nmap

# Go to app folder
WORKDIR /usr/src/app

# Install required python packages
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create volume for persistent information
VOLUME [ "/usr/src/app/persistent" ]

CMD [ "python", "-u", "main.py" ]
