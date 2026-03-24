from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
import requests
import threading
import time

API_URL = "http://127.0.0.1:5000/api/analyze_traffic"

class FlowMonitor(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FlowMonitor, self).__init__(*args, **kwargs)

        self.datapaths = {}

        self.monitor_thread = threading.Thread(target=self.monitor)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

    # register switches
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):

        datapath = ev.datapath

        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    # monitoring loop
    def monitor(self):

        while True:
            for dp in self.datapaths.values():
                self.request_stats(dp)

            time.sleep(5)

    # request flow statistics
    def request_stats(self, datapath):

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    # receive flow statistics
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):

        body = ev.msg.body

        flows = []

        for stat in body:

            if stat.priority == 0:
                continue

            flow = {
                "src_ip": stat.match.get("ipv4_src", "unknown"),
                "dst_ip": stat.match.get("ipv4_dst", "unknown"),
                "packets": stat.packet_count,
                "bytes": stat.byte_count
            }

            flows.append(flow)

        # send to Flask backend
        try:
            requests.post(API_URL, json={"flows": flows})
        except:
            pass