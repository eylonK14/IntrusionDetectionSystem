#!/usr/bin/env python3

import ast
import pprint
import flet as ft
import scapy.all as scapy
from collections import defaultdict


# Flow tracker
class Flow:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, proto):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto = proto
        self.packets_sent = 0
        self.packets_received = 0
        self.size_of_sent_data = 0
        self.size_of_received_data = 0

    def __str__(self):
        return f"""
Flow {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}
Protocol: {self.proto}
Packets Sent: {self.packets_sent}
Packets Received: {self.packets_received}
Sent Data (bytes): {self.size_of_sent_data}
Received Data (bytes): {self.size_of_received_data}
"""


# Dictionary to store flows
flows = defaultdict(Flow)


# Function to create flow key based on 5-tuple
def create_flow_key(packet):
    # Extract necessary information for the 5-tuple
    src_ip = packet[scapy.IP].src
    dst_ip = packet[scapy.IP].dst
    # proto_num = packet[scapy.IP].proto
    # proto = proto_name_by_num(proto_num)
    proto = packet.payload.layers()[1].__name__
    src_port = 0
    dst_port = 0

    # For protocols like TCP and UDP, ports are important
    if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP):
        src_port = packet.sport
        dst_port = packet.dport

    # Ensure the lower IP and port always come first in the flow key
    if (src_ip, src_port) > (dst_ip, dst_port):
        src_ip, dst_ip = dst_ip, src_ip
        src_port, dst_port = dst_port, src_port

    return (src_ip, dst_ip, src_port, dst_port, proto)


def main(page: ft.Page) -> None:
    def dropdown_changed(e: ft.ControlEvent):
        pass

    def packet_handler(packet):
        if packet.haslayer(scapy.IP):
            # Create a unique flow key based on the 5-tuple
            flow_key = create_flow_key(packet)

            # Check if this flow already exists
            if flow_key not in flows:
                flows[flow_key] = Flow(*flow_key)
                flow_list.options.append(ft.dropdown.Option(flow_key))

            # Determine whether the packet is sent or received
            if packet[scapy.IP].src == flows[flow_key].src_ip:
                flows[flow_key].packets_sent += 1
            else:
                flows[flow_key].packets_received += 1

            # Output flow information in real-time
            # os.system("clear")  # Clear the console for better readability
            print(f"Updated Flow Information:\n{flows[flow_key]}")
            # print(f'{flows.keys()=}')
            # print(dict(flows))

            packet_info.value = f'{flows[flow_key]}'
            page.update()
            # Prints the nicely formatted dictionary
            pprint.pprint(dict(flows))

    def button_clicked(e: ft.ControlEvent):
        sniffer = scapy.AsyncSniffer(prn=packet_handler, iface=dropdown.value)
        sniffer.start()

    def on_keyboard(e: ft.KeyboardEvent):
        if e.ctrl and e.key == 'Q':
            page.open(confirm_dialog)

    def handle_window_event(e: ft.ControlEvent):
        if e.data == "close":
            page.open(confirm_dialog)

    def yes_click(e: ft.ControlEvent):
        page.window.destroy()

    def no_click(e: ft.ControlEvent):
        page.close(confirm_dialog)

    def flow_selected(e: ft.ControlEvent):
        flow_info.value = f'{flows[ast.literal_eval(flow_list.value)]}'
        page.update()

    page.title = 'ids gui'
    page.vertical_alignment = ft.MainAxisAlignment.CENTER
    page.window.prevent_close = True
    page.window.on_event = handle_window_event
    page.on_keyboard_event = on_keyboard
    # page.theme_mode = 'light'

    dropdown: ft.Dropdown = ft.Dropdown(
        label='interface',
        hint_text='Choose an inteeface',
        on_change=dropdown_changed,
        options=[
            ft.dropdown.Option(inter)
            for inter in scapy.get_if_list()
        ]
    )

    button: ft.CupertinoFilledButton = ft.CupertinoFilledButton(
        content=ft.Text('Start Sniffing'),
        opacity_on_click=0.3,
        on_click=button_clicked
    )

    flow_list: ft.Dropdown = ft.Dropdown(
        label='flows',
        hint_text='show info on flow',
        on_change=flow_selected
    )

    packet_info: ft.Text = ft.Text('lorem ipsum')

    flow_info: ft.Text = ft.Text('lorem ipsum')

    confirm_dialog = ft.AlertDialog(
        modal=True,
        title=ft.Text("Please confirm"),
        content=ft.Text("Do you really want to exit this app?"),
        actions=[
            ft.ElevatedButton("Yes", on_click=yes_click),
            ft.OutlinedButton("No", on_click=no_click),
        ],
        actions_alignment=ft.MainAxisAlignment.END,
    )

    page.add(
        ft.Column(
            [dropdown, button, flow_list, packet_info, flow_info],
            alignment=ft.MainAxisAlignment.CENTER
        )
    )


if __name__ == "__main__":
    ft.app(target=main)
