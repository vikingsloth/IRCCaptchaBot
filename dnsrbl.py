from concurrent.futures import ProcessPoolExecutor
import dns
from dns import resolver
import logging

LOG = logging.getLogger('DNS')

# Static function wrapper to be pickleable by ProcessPoolExecutor
def dns_query(qname, qtype):
    r = resolver.Resolver()
    return r.query(qname, qtype)

class DNS(object):
    def __init__(self, max_concurrent = 5):
        self.pool = ProcessPoolExecutor(max_workers = max_concurrent)
        self.queue = []

    # Query A record and return a list of IPs
    def host(self, host, callback, *cb_args):
        answer = self.pool.submit(dns_query, host, dns.rdatatype.A)
        self.queue.append([answer, callback, cb_args])

    def qlen(self):
        return len(self.queue)

    def processAnswers(self):
        count = 0
        unfinished = []
        for item in self.queue:
            future, callback, cb_args = item
            if future.done():
                count += 1
                LOG.debug("Processing answer")
                try:
                    answer = future.result()
                except dns.resolver.NoAnswer:
                    continue
                except Exception as e:
                    LOG.exception(e)
                callback(answer, *cb_args)
            else:
                # save incomplete futures to a new list and overwrite the 
                # old list after we're done
                unfinished.append(item)
        self.queue = unfinished
        return count
