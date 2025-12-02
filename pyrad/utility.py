def tlv_name_to_codes(dictionary, tlv):
    """
    recursive function to change all the keys in a TLV from strings to
    codes

    :param dictionary: dictionary containing attribute name to key mappings
    :param tlv: tlv with attribute names
    :return: tlv with attribute keys
    """
    updated = {}
    for key, value in tlv.items():
        code = dictionary.attrindex[key]

        #  in nested structures, pyrad stored the entire OID in a single tuple
        #  but we only want the last code
        if isinstance(code, tuple):
            code = code[-1]

        if isinstance(value, str):
            updated[code] = value
        else:
            updated[code] = tlv_name_to_codes(dictionary, value)
    return updated


def vsa_name_to_codes(dictionary, vsa):
    updated = {'Vendor-Specific': {}}

    for vendor, tlv in vsa['Vendor-Specific'].items():
        vendor_id = dictionary.vendors[vendor]
        vendor_tlv = tlv_name_to_codes(dictionary, tlv)
        updated['Vendor-Specific'][vendor_id] = vendor_tlv

    return updated
