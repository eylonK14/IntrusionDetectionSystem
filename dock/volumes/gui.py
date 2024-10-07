#!/usr/bin/env python3

import ast
import pprint
import threading
import flet as ft
import rulebook as rb
import scapy.all as scapy
import packet_handler as ph

c = 0
sem = threading.Semaphore()


def get_route_list(route):
    return [item for item in route.split("/") if item != ""]


def main(page: ft.Page) -> None:
    current_filters = [None]*6

    def src_ip_selected(e: ft.ControlEvent):
        current_filters[0] = src_ip_filter.value
        append_according_to_filters()

    def dst_ip_selected(e: ft.ControlEvent):
        current_filters[1] = dst_ip_filter.value
        append_according_to_filters()

    def src_port_selected(e: ft.ControlEvent):
        current_filters[2] = int(src_port_filter.value)
        append_according_to_filters()

    def dst_port_selected(e: ft.ControlEvent):
        current_filters[3] = int(dst_port_filter.value)
        append_according_to_filters()

    def protocol_selected(e: ft.ControlEvent):
        current_filters[4] = protocol_filter.value
        append_according_to_filters()

    def direction_changed(e: ft.ControlEvent):
        current_filters[5] = direction_filter.value
        direction_filter.label = f"direction: {'outgoing' if direction_filter.value else 'ingoing'}"
        append_according_to_filters()

    def handle_change(e: ft.ControlEvent):
        src_ip_filter.disabled = True
        dst_ip_filter.disabled = True
        src_port_filter.disabled = True
        dst_port_filter.disabled = True
        protocol_filter.disabled = True
        direction_filter.disabled = True
        for i in ast.literal_eval(e.data):
            if i == 'src_ip':
                src_ip_filter.disabled = False
            elif i == 'dst_ip':
                dst_ip_filter.disabled = False
            elif i == 'src_port':
                src_port_filter.disabled = False
            elif i == 'dst_port':
                dst_port_filter.disabled = False
            elif i == 'protocol':
                protocol_filter.disabled = False
            elif i == 'direction':
                direction_filter.disabled = False
        if src_ip_filter.disabled:
            src_ip_filter.options = []
            current_filters[0] = None
        if dst_ip_filter.disabled:
            dst_ip_filter.options = []
            current_filters[1] = None
        if src_port_filter.disabled:
            src_port_filter.options = []
            current_filters[2] = None
        if dst_port_filter.disabled:
            dst_port_filter.options = []
            current_filters[3] = None
        if protocol_filter.disabled:
            protocol_filter.options = []
            current_filters[4] = None
        if direction_filter.disabled:
            direction_filter.label = 'direction'
            current_filters[5] = None
        page.update()

    def theme_changed(e: ft.ControlEvent):
        page.theme_mode = (
            ft.ThemeMode.DARK
            if page.theme_mode == ft.ThemeMode.LIGHT
            else ft.ThemeMode.LIGHT
        )
        theme_toggle.label = (
            "Light theme"
            if page.theme_mode == ft.ThemeMode.LIGHT
            else "Dark theme"
        )
        page.update()

    def dropdown_changed(e: ft.ControlEvent):
        sniff_toggle.disabled = False
        page.update()

    def append_according_to_filters(key=None):
        # print(f'{current_filters=}')
        flows_set = set()
        for key, flow in rb.flows.items():
            # print(f'{key=}')
            flag = True
            for i in range(5):
                if current_filters[i] is not None and current_filters[i] != key[i]:
                    flag = False
            if current_filters[5] is not None and current_filters[5] != flow.outgoing:
                flag = False
            if flag:
                flows_set.add(key)
        flow_list.options = [ft.dropdown.Option(key) for key in flows_set]
        page.update()

    def handle_packet(packet, from_pcap=False):
        if not packet.haslayer(scapy.IP):
            return

        # Create a unique flow key based on the 5-tuple
        key = ph.create_flow_key(packet)
        # Get the payload size for this packet
        payload_size = ph.get_payload_size(packet)

        # Check if this flow already exists
        if key not in rb.flows:
            rb.flows[key] = ph.Flow(*key)
            rb.flows[key].outgoing = from_pcap
            routes = set()
            for line in scapy.read_routes():
                routes.add(line[4])
            if rb.flows[key].src_ip in routes:
                rb.flows[key].outgoing = True
            populate_filters(key)
            append_according_to_filters()
            # flow_list.options.append(ft.dropdown.Option(key))

        rb.flows[key].packets_sent += 1
        rb.flows[key].size_of_sent_data += payload_size

        rb.add_to_dns_cached_ips(packet, key)

        sus_flag, sus_str = rb.check_suspicious(packet, key, from_pcap)
        if sus_flag:
            page.controls.append(
                ft.Text(f'suspicious: {key}\n{sus_str}\n', color='red')
            )
        # Output flow information in real-time
        # os.system("clear")  # Clear the console for better readability
        # print(f"Updated Flow Information:\n{flows[flow_key]}")
        # print(f'{flows.keys()=}')
        # print(dict(flows))
        # Prints the nicely formatted dictionary
        # pprint.pprint(dict(flows))
        # print(f'{packet.layers()=}')

        packet_info.value = f'{rb.flows[key]}'
        page.update()

    def populate_filters(key):
        src_ip_set.add(rb.flows[key].src_ip)
        dst_ip_set.add(rb.flows[key].dst_ip)
        src_port_set.add(rb.flows[key].src_port)
        dst_port_set.add(rb.flows[key].dst_port)
        protocol_set.add(rb.flows[key].proto)
        src_ip_filter.options = [ft.dropdown.Option(i) for i in src_ip_set]
        dst_ip_filter.options = [ft.dropdown.Option(i) for i in dst_ip_set]
        src_port_filter.options = [ft.dropdown.Option(i) for i in src_port_set]
        dst_port_filter.options = [ft.dropdown.Option(i) for i in dst_port_set]
        protocol_filter.options = [ft.dropdown.Option(i) for i in protocol_set]

    def pick_files_result(e: ft.FilePickerResultEvent):
        iface_chooser.disabled = True
        path = e.files[0].path
        for packet in scapy.PcapReader(path):
            handle_packet(packet, True)

    def toggle_sniff(e: ft.ControlEvent):
        if sniff_toggle.value:
            sniffer.start()
            sniff_toggle.label = 'Stop Sniffing'
        else:
            sniffer.stop()
            sniff_toggle.label = 'Start Sniffing'
        page.update()

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
        flow_info.value = f'{rb.flows[ast.literal_eval(flow_list.value)]}'
        page.update()

    page.title = 'ids gui'
    page.vertical_alignment = ft.MainAxisAlignment.CENTER
    page.window.prevent_close = True
    page.window.on_event = handle_window_event
    page.on_keyboard_event = on_keyboard
    page.scroll = ft.ScrollMode.ALWAYS
    page.theme_mode = ft.ThemeMode.DARK

    theme_toggle = ft.Switch(label="Dark theme", on_change=theme_changed)

    iface_chooser = ft.Dropdown(
        label='interface',
        hint_text='Choose an interface',
        on_change=dropdown_changed,
        options=[
            ft.dropdown.Option(inter)
            for inter in scapy.get_if_list()
        ]
    )

    sniff_toggle = ft.Switch(
        label='Start Sniffing', on_change=toggle_sniff, disabled=True
    )

    filter_by = ft.SegmentedButton(
        on_change=handle_change,
        selected_icon=ft.Icon(ft.icons.CHECK_BOX),
        selected={},
        allow_empty_selection=True,
        allow_multiple_selection=True,
        segments=[
            ft.Segment(
                value="src_ip",
                label=ft.Text("src ip"),
                icon=ft.Icon(ft.icons.LOOKS_ONE),
            ),
            ft.Segment(
                value="dst_ip",
                label=ft.Text("dest ip"),
                icon=ft.Icon(ft.icons.LOOKS_TWO),
            ),
            ft.Segment(
                value="src_port",
                label=ft.Text("src port"),
                icon=ft.Icon(ft.icons.LOOKS_3),
            ),
            ft.Segment(
                value="dst_port",
                label=ft.Text("dest port"),
                icon=ft.Icon(ft.icons.LOOKS_4),
            ),
            ft.Segment(
                value="protocol",
                label=ft.Text("protocol"),
                icon=ft.Icon(ft.icons.LOOKS_5),
            ),
            ft.Segment(
                value="direction",
                label=ft.Text("direction"),
                icon=ft.Icon(ft.icons.LOOKS_6),
            ),
        ],
    )

    src_ip_filter = ft.Dropdown(
        label='source ip',
        hint_text='show info on flow',
        on_change=src_ip_selected,
        disabled=True
    )

    dst_ip_filter = ft.Dropdown(
        label='destination ip',
        hint_text='show info on flow',
        on_change=dst_ip_selected,
        disabled=True
    )

    src_port_filter = ft.Dropdown(
        label='source port',
        hint_text='show info on flow',
        on_change=src_port_selected,
        disabled=True
    )

    dst_port_filter = ft.Dropdown(
        label='destination port',
        hint_text='show info on flow',
        on_change=dst_port_selected,
        disabled=True
    )

    protocol_filter = ft.Dropdown(
        label='protocol',
        hint_text='show info on flow',
        on_change=protocol_selected,
        disabled=True
    )

    direction_filter = ft.Switch(
        label='direction',
        on_change=direction_changed,
        disabled=True
    )

    src_ip_set = set()
    dst_ip_set = set()
    src_port_set = set()
    dst_port_set = set()
    protocol_set = set()

    flow_list = ft.Dropdown(
        label='flows',
        hint_text='show info on flow',
        on_change=flow_selected
    )
    print(f'{flow_list.options=}')

    packet_info: ft.Text = ft.Text()

    flow_info: ft.Text = ft.Text()

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

    pick_files_dialog = ft.FilePicker(on_result=pick_files_result)
    page.overlay.append(pick_files_dialog)

    page.add(
        ft.Column(
            [
                ft.ElevatedButton(
                    "Pick files",
                    icon=ft.icons.UPLOAD_FILE,
                    on_click=lambda _: pick_files_dialog.pick_files(
                        allow_multiple=False,
                        allowed_extensions=['pcap', 'pcapng']
                    ),
                ),
                theme_toggle,
                iface_chooser,
                sniff_toggle,
                filter_by,
                src_ip_filter,
                dst_ip_filter,
                src_port_filter,
                dst_port_filter,
                protocol_filter,
                direction_filter,
                flow_list,
                packet_info,
                flow_info,
            ],
            alignment=ft.MainAxisAlignment.CENTER,
        )
    )
    scapy.load_layer('http')
    sniffer = scapy.AsyncSniffer(prn=handle_packet, iface=iface_chooser.value)


if __name__ == "__main__":
    ft.app(target=main)
