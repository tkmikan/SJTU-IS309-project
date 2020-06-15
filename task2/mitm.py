import threading

from cca2 import hack


class Hook:
    def request(self, flow):
        if flow.request.path == '/upload':
            try:
                t = threading.Thread(target=hack, args=(flow.request.cookies['session'], flow.request.urlencoded_form['aes'], flow.request.urlencoded_form['wup']))
                t.start()
            except Exception as e:
                print(e)


addons = [Hook()]
