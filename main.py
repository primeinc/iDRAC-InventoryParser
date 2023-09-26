import argparse
import re  # Import the regular expression module
from xml.etree import ElementTree as ET
from collections import defaultdict

# Function to generate consolidated Markdown table


def parse_hardware_info(file_path, interested_attributes=None):
    # Load your XML file
    tree = ET.parse(file_path)
    root = tree.getroot()

    # Create a dictionary to store the data
    hardware_info = defaultdict(dict)

    # Loop through each component
    for child in root:
        component_name = child.attrib.get("Classname", "Unknown")
        key = child.attrib.get("Key", "Unknown")

        # Skip this component if it's not in interested_attributes when provided
        if (
            interested_attributes is not None
            and component_name not in interested_attributes
        ):
            continue

        # Create a nested dictionary for this component
        hardware_info[component_name][key] = {}

        # Loop through each child of the current child (attributes of the component)
        for sub_child in child:
            attribute_name = sub_child.attrib.get("NAME", "Unknown")

            # Skip filtering if interested_attributes is None
            if interested_attributes is None or (
                component_name in interested_attributes
                and any(
                    re.match(pattern, key)
                    and attribute_name
                    in interested_attributes[component_name].get(pattern, [])
                    for pattern in interested_attributes[component_name]
                )
            ):
                # Loop through the sub-attributes to get their values
                for sub_sub_child in sub_child:
                    if sub_sub_child.tag == "DisplayValue":
                        hardware_info[component_name][key][
                            attribute_name
                        ] = sub_sub_child.text

                        # Special case to calculate SizeInGigabytes for Disk.Bay.*
                        if (
                            component_name == "DCIM_PhysicalDiskView"
                            and attribute_name == "SizeInBytes"
                        ):
                            try:
                                size_in_bytes = int(sub_sub_child.text.split(" ")[0])
                                size_in_gb = size_in_bytes / (
                                    1024**3
                                )  # Bytes to Gigabytes
                                hardware_info[component_name][key][
                                    "SizeInGigabytes"
                                ] = f"{size_in_gb} GB"
                            except ValueError:
                                hardware_info[component_name][key][
                                    "SizeInGigabytes"
                                ] = "Conversion Error"

    return hardware_info


def unique_hardware_info(
    hardware_info, comparison_attributes, interested_attributes=None
):
    # Initialize a dictionary to store the summarized data
    unique_hardware_info = defaultdict(list)

    # Loop through each hardware component
    for component, keys in hardware_info.items():
        if component not in comparison_attributes and (
            interested_attributes is None or component not in interested_attributes
        ):
            continue  # Skip this component if it's not in either list
        # Initialize a dictionary to hold unique components and their counts
        unique_components = defaultdict(int)

        # Get the comparison attribute for this component type
        comp_attr = comparison_attributes.get(component, [])

        # Loop through each key (e.g., each individual DIMM, Disk, etc.)
        for key, attributes in keys.items():
            # Create a subset of attributes based on the comparison attribute
            comparison_data = {attr: attributes.get(attr, "N/A") for attr in comp_attr}

            # Special case for NICView: Remove MAC address from ProductName
            if component == "DCIM_NICView" and "ProductName" in comparison_data:
                comparison_data["ProductName"] = re.sub(
                    r" - [A-F0-9:]+$", "", comparison_data["ProductName"]
                )

            # Convert the comparison_data dictionary to a tuple of its items so it can be hashed
            comparison_tuple = tuple(sorted(comparison_data.items()))

            # Increment the count for this unique set of attributes
            unique_components[comparison_tuple] += 1

        # Store the summarized information in the new dictionary
        unique_hardware_info[component] = unique_components

    # Pretty print the summarized dictionary
    return unique_hardware_info


def raw_output(hardware_info, type="all"):
    # Pretty print the dictionary
    if type == "unique":
        for component, unique_components in hardware_info.items():
            print(f"Component: {component}")
            for comparison_tuple, count in unique_components.items():
                print(f"  Count: {count}")
                comparison_dict = dict(comparison_tuple)
                for attribute, display_value in comparison_dict.items():
                    print(f"    {attribute} = {display_value}")
        print("\n")
    else:
        for component, keys in hardware_info.items():
            print(f"Component: {component}")
            for key, attributes in keys.items():
                print(f"  {key}")
                for attribute, display_value in attributes.items():
                    print(f"    {attribute} = {display_value}")
        print("\n")


def generate_md_table(hardware_info, type="all"):
    md_tables = []
    if type == "unique":
        for component, unique_components in hardware_info.items():
            # Generate Markdown table header
            headers = ["Count"] + [
                key for key, _ in next(iter(unique_components.keys()))
            ]
            md_table = [
                f"### {component}",
                "| " + " | ".join(headers) + " |",
                "| " + " :--: |" * len(headers),
            ]

            # Generate Markdown table rows
            for comparison_tuple, count in unique_components.items():
                row = [str(count)] + [value for _, value in comparison_tuple]
                md_table.append("| " + " | ".join(row) + " |")

            md_tables.append("\n".join(md_table))
        return "\n\n".join(md_tables)
    else:  # Handling for raw data
        for component, keys in hardware_info.items():
            # Generate Markdown table header; assume all keys have the same attributes
            headers = next(iter(keys.values())).keys()
            md_table = [
                f"### {component}",
                "| Key | " + " | ".join(headers) + " |",
                "| :--: | " + " :--: |" * len(headers),
            ]

            # Generate Markdown table rows
            for key, attributes in keys.items():
                row = [key] + [
                    str(attributes.get(header, "N/A")) for header in headers
                ]  # Convert None to 'N/A' and everything to string
                md_table.append("| " + " | ".join(row) + " |")

            md_tables.append("\n".join(md_table))

    return "\n\n".join(md_tables)


def generate_consolidated_md_table(hardware_info, type="all"):
    # Extract system information
    system_info = hardware_info.get("DCIM_SystemView", {})
    system_info_tuple = next(iter(system_info.keys()), {})
    system_info = dict(system_info_tuple)
    model = system_info.get("Model", "Unknown")
    service_tag = system_info.get("ServiceTag", "Unknown")

    # Initialize Markdown table
    md_table = [f"### {model} - {service_tag}", "| Info | Count |", "| :-- | :--: |"]

    if type == "unique":
        # Handle unique hardware information
        for component, unique_components in hardware_info.items():
            if component == "DCIM_SystemView":
                # We've already used this for the table title, so skip
                continue
            for comparison_tuple, count in unique_components.items():
                comparison_dict = dict(comparison_tuple)
                info_str = generate_info_string(component, comparison_dict)
                md_table.append(f"| {info_str} | {count} |")
    else:
        # Handle non-unique hardware information
        for component, keys in hardware_info.items():
            for key, attributes in keys.items():
                info_str = generate_info_string(component, attributes)
                md_table.append(
                    f"| {info_str} | 1 |"
                )  # Assuming each entry counts as 1

    return "\n".join(md_table)


def generate_info_string(component, attributes):
    if component == "DCIM_MemoryView":
        return f"{attributes.get('Model', '')} - {attributes.get('PartNumber', '')} - {attributes.get('Speed', '')} - {attributes.get('Size', '')}"
    elif component == "DCIM_PhysicalDiskView":
        return f"{attributes.get('MediaType', '')} - {attributes.get('Model', '')} - {attributes.get('SizeInGigabytes', '')}"
    elif component == "DCIM_CPUView":
        return attributes.get("Model", "")
    elif component == "DCIM_PowerSupplyView":
        return attributes.get("Model", "").strip()
    elif component == "DCIM_SystemView":
        return ""
    else:
        return attributes.get("ProductName", "")


if __name__ == "__main__":
    # TODO: Currently --unique implies --filtered, lacking a test case but output is the same with or without --filtered
    # Initialize argument parser
    parser = argparse.ArgumentParser(description="Parse hardware information.")
    parser.add_argument("file_path", type=str, help="Path to the XML file.")
    parser.add_argument(
        "output_type", choices=["raw", "md"], help="Output type: raw or Markdown."
    )
    parser.add_argument(
        "--filtered", action="store_true", help="Apply attribute filtering."
    )
    parser.add_argument(
        "--unique",
        action="store_true",
        help="Output the flattened unique hardware configuration.",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="For MD table to bet better formatted. Implies --unique.",
    )
    # Parse arguments
    args = parser.parse_args()

    if args.pretty:
        args.unique = True

    # Define the attributes you are interested in for each component
    # fmt: off
    # TODO: move this to a separate file
    filtered_attributes = {
        "DCIM_ControllerView": {
            "RAID.Integrated.1-1": ["CacheSizeInMB", "SASAddress", "ProductName", "DeviceDescription"]
        },
        "DCIM_MemoryView": {
            "DIMM.Socket.*": ["Rank", "Model", "PartNumber", "Manufacturer", "Size", "Speed", "SerialNumber"]
        },
        "DCIM_SystemView": {
            "System.Embedded.1": [
                "BoardPartNumber", "BoardSerialNumber", "AssetTag", "HostName", "BIOSReleaseDate",
                "BIOSVersionString", "ChassisServiceTag", "ExpressServiceCode", "ServiceTag",
                "Manufacturer", "Model", "LifecycleControllerVersion", "SystemGeneration",
            ]
        },
        "DCIM_NICView": {
            "NIC.Integrated.*": [
                "Protocol", "MediaType", "VendorName", "PermanentMACAddress",
                "CurrentMACAddress", "ProductName", "DeviceDescription",
            ]
        },
        "DCIM_PowerSupplyView": {
            "PSU.Slot.*": [
                "TotalOutputPower", "Manufacturer", "PartNumber",
                "SerialNumber", "Model", "DeviceDescription",
            ]
        },
        "DCIM_PhysicalDiskView": {
            "Disk.Bay.*": [
                "DriveFormFactor", "MaxCapableSpeed", "MediaType", "BlockSizeInBytes", "BusProtocol", "SerialNumber", "Revision", "Model", "SizeInBytes", "Slot", "Connector",
                "RaidStatus", "DeviceDescription",
            ],
            "Disk.Direct.*": [
                "DriveFormFactor", "MaxCapableSpeed", "MediaType", "BlockSizeInBytes",
                "BusProtocol", "SerialNumber", "Revision", "Model", "SizeInBytes",
                "Slot", "Connector", "RaidStatus", "DeviceDescription",
            ],
        },
        "DCIM_EnclosureView": {
            "Enclosure.Internal.0-1:RAID.Integrated.1-1": [
                "ProductName", "SlotCount", "Version", "DeviceDescription",
            ]
        },
        "DCIM_CPUView": {
            "CPU.Socket.*": [
                "Cache3Size", "Cache2Size", "Cache1Size", "Model", "Manufacturer",
                "TurboModeCapable", "VirtualizationTechnologyCapable", "HyperThreadingCapable",
                "Characteristics", "NumberOfProcessorCores", "NumberOfEnabledThreads",
                "NumberOfEnabledCores", "MaxClockSpeed", "CPUFamily", "DeviceDescription",
            ]
        },
    }
    # fmt: on
    # Define comparison attributes for each component type
    unique_comparison_attributes = {
        "DCIM_ControllerView": ["ProductName"],
        "DCIM_MemoryView": ["Model", "PartNumber", "Size", "Speed"],
        "DCIM_SystemView": ["Model", "ServiceTag"],
        "DCIM_NICView": ["ProductName"],
        "DCIM_PowerSupplyView": ["Model"],
        "DCIM_PhysicalDiskView": ["Model", "MediaType", "SizeInGigabytes"],
        "DCIM_EnclosureView": ["ProductName"],
        "DCIM_CPUView": ["Model"],
    }

    # Call function based on mode
    # if args.output_type == 'raw' or args.output_type == 'md':
    hardware_info = parse_hardware_info(
        args.file_path, filtered_attributes if args.filtered else None
    )

    if args.unique:
        hardware_info = unique_hardware_info(
            hardware_info, unique_comparison_attributes
        )

    if args.output_type == "md" and args.pretty:
        print(generate_consolidated_md_table(hardware_info, "unique"))
    elif args.output_type == "md":
        print(generate_md_table(hardware_info, "unique" if args.unique else "all"))
    elif args.output_type == "raw":
        raw_output(hardware_info, "unique" if args.unique else "all")
