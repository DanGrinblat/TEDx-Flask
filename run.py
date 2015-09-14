from app import app
from flask_sslify import SSLify
import ssl

sslify = SSLify(app)
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.load_cert_chain('server.cert', 'server.key')

if __name__ == '__main__':
	app.run(host='127.0.0.1',
        debug = True)