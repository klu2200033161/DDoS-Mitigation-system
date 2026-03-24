from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
import requests

API_URL = "http://127.0.0.1:5000/analyze"

class DDOSController(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDOSController, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):

        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser

        pkt_len = msg.total_len

        data = {
            "packet_size": pkt_len
        }

        try:
            response = requests.post(API_URL, json=data)
            result = response.json()

            if result["attack"] == True:
                self.logger.info("Attack detected!")

        except:
            pass