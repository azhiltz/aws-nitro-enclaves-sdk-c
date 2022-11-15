import cbor2 as cbor
import base64

def attestation_cbor2json(cbor_data):
    attestation_dict = {}
    attestation_dict["module_id"] = cbor_data["module_id"]
    attestation_dict["timestamp"] = cbor_data["timestamp"]
    attestation_dict["digest"] = cbor_data["digest"]
    pcrs_data = cbor_data["pcrs"]
    
    pcrs = []
    for k, v in pcrs_data.items():
        pcr = {}
        pcr[k] = base64.b64encode(v)
        pcrs.append(pcr)
    attestation_dict["pcrs"] = pcrs
    attestation_dict["certificate"] = []
    if cbor_data["certificate"]:
        attestation_dict["certificate"] = base64.b64encode(cbor_data["certificate"])
    
    cabundle = []
    for i in cbor_data["cabundle"]:
        cabundle.append(base64.b64encode(i))
    attestation_dict["cabundle"] = cabundle
    if cbor_data["public_key"]:
        attestation_dict["public_key"] = base64.b64encode(cbor_data["public_key"])
    if cbor_data["user_data"]:
        attestation_dict["user_data"] = base64.b64encode(cbor_data["user_data"])
    if  cbor_data["nonce"]:
        attestation_dict["nonce"] = base64.b64encode(cbor_data["nonce"])

    return attestation_dict

def get_all_items(base64_content):
    cbor_all = cbor.loads(base64_content)
    if len(cbor_all) < 4:
        raise ValueError("cbor data length must be 4")
    algdict = cbor.loads(cbor_all[0])
    v = algdict.get(1, 0)
    signature_alg = None
    if v == -35:
        signature_alg = "ECDS384"
    attest_doc = attestation_cbor2json(cbor.loads(cbor_all[2]))

    signature = base64.b64encode(cbor_all[3])

    return signature_alg, attest_doc, signature

def print_kv(cbor_list):
    for I in cbor_list:
        if not isinstance(I, bytes):
            print(I)
            continue
        print("**************")
        cbor_t = cbor.loads(I)
        if not isinstance(cbor_t, dict):
            print(len(I), base64.b64encode(I))
            continue
        for k,v in cbor_t.items():
            print(k)

if __name__ == "__main__":
    attdata = b'\x84D\xa1\x018"\xa0Y\x11\xe8\xa9imodule_idx\'i-05a940be8fe64c488-enc018478f91665dcb5fdigestfSHA384itimestamp\x1b\x00\x00\x01\x84x\xf9\x86\xd2dpcrs\xb0\x00X0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01X0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02X0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03X0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04X0%\xbc\x92\x8d!\xd8$\xef\x9aL.\xb81kY\xa2\x11\xef\xdfF#\xb5\xd2n\xb8\xf3\r\xe80^\xfeku\x074\xf5\x96\xfc\xfeA\x1a\x8d\xe6Ll2\x1cC\x05X0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06X0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07X0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08X0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\tX0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\nX0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0bX0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0cX0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\rX0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0eX0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0fX0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00kcertificateY\x02\x7f0\x82\x02{0\x82\x02\x01\xa0\x03\x02\x01\x02\x02\x10\x01\x84x\xf9\x16e\xdc\xb5\x00\x00\x00\x00cr\xf0\x010\n\x06\x08*\x86H\xce=\x04\x03\x030\x81\x8e1\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\x08\x0c\nWashington1\x100\x0e\x06\x03U\x04\x07\x0c\x07Seattle1\x0f0\r\x06\x03U\x04\n\x0c\x06Amazon1\x0c0\n\x06\x03U\x04\x0b\x0c\x03AWS1907\x06\x03U\x04\x03\x0c0i-05a940be8fe64c488.us-east-1.aws.nitro-enclaves0\x1e\x17\r221115014846Z\x17\r221115044849Z0\x81\x931\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\x08\x0c\nWashington1\x100\x0e\x06\x03U\x04\x07\x0c\x07Seattle1\x0f0\r\x06\x03U\x04\n\x0c\x06Amazon1\x0c0\n\x06\x03U\x04\x0b\x0c\x03AWS1>0<\x06\x03U\x04\x03\x0c5i-05a940be8fe64c488-enc018478f91665dcb5.us-east-1.aws0v0\x10\x06\x07*\x86H\xce=\x02\x01\x06\x05+\x81\x04\x00"\x03b\x00\x04&5,\xc2\x80\xe8]6}\xdacB\xf7\x99\xc1\x0c\xe5\xac\xa0\xd4\x06K\xa4\xbf\xe7\x08b"\x9e7\x89\xc3\x84k\xaa!\t\x0c\x0e\xfflFw\\Z\x99\xc1\x1eq>\xd7\xff\x9b\x93\xe4u\xd7f\xa5\x82Ny}\x115JL\x8e\xa7\xd0\xc5\xf4\x9e|q\xda\xcc\x80?\xe2\x03\xda\xac\x93\xf9\x85\x16\xc8\t8R\'\xc9\x84\x89\xb7\xa3\x1d0\x1b0\x0c\x06\x03U\x1d\x13\x01\x01\xff\x04\x020\x000\x0b\x06\x03U\x1d\x0f\x04\x04\x03\x02\x06\xc00\n\x06\x08*\x86H\xce=\x04\x03\x03\x03h\x000e\x020.i\xb55\xaao\xb2\xcaS\xc6"\x86\xd1\xa0m\xe1\xaf2\x9eW5\x10\x02\xe2\xa7nE\xaa\xe9\xd6\xe1F\x07\xfcJq1b\xa0Z\xbc[\xee\xa8\xc2Y\xbd&\x021\x00\xe4\xec\xc3?$JX\xa8"\xef^\x17\xb2\x81Q\x02\xd0MD\xac\x8d"\xd25\xa7\x9c\xe0\xa7\xf3\xfc%C@#\xeb_^\xd8,"\x96\xad(\xf9\xc5R1\xabhcabundle\x84Y\x02\x150\x82\x02\x110\x82\x01\x96\xa0\x03\x02\x01\x02\x02\x11\x00\xf91uh\x1b\x90\xaf\xe1\x1dF\xcc\xb4\xe4\xe7\xf8V0\n\x06\x08*\x86H\xce=\x04\x03\x030I1\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x0f0\r\x06\x03U\x04\n\x0c\x06Amazon1\x0c0\n\x06\x03U\x04\x0b\x0c\x03AWS1\x1b0\x19\x06\x03U\x04\x03\x0c\x12aws.nitro-enclaves0\x1e\x17\r191028132805Z\x17\r491028142805Z0I1\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x0f0\r\x06\x03U\x04\n\x0c\x06Amazon1\x0c0\n\x06\x03U\x04\x0b\x0c\x03AWS1\x1b0\x19\x06\x03U\x04\x03\x0c\x12aws.nitro-enclaves0v0\x10\x06\x07*\x86H\xce=\x02\x01\x06\x05+\x81\x04\x00"\x03b\x00\x04\xfc\x02T\xeb\xa6\x08\xc1\xf3hp\xe2\x9a\xda\x90\xbeF82\x92sn\x89K\xff\xf6r\xd9\x89DKPQ\xe54\xa4\xb1\xf6\xdb\xe3\xc0\xbcX\x1a2\xb7\xb1v\x07\x0e\xde\x12\xd6\x9a?\xea!\x1bf\xe7R\xcf}\xd1\xdd\t_o\x13p\xf4\x17\x08C\xd9\xdc\x10\x01!\xe4\xcfc\x01(\tfD\x87\xc9yb\x840M\xc5?\xf4\xa3B0@0\x0f\x06\x03U\x1d\x13\x01\x01\xff\x04\x050\x03\x01\x01\xff0\x1d\x06\x03U\x1d\x0e\x04\x16\x04\x14\x90%\xb5\r\xd9\x05G\xe7\x96\xc3\x96\xfar\x9d\xcf\x99\xa9\xdfK\x960\x0e\x06\x03U\x1d\x0f\x01\x01\xff\x04\x04\x03\x02\x01\x860\n\x06\x08*\x86H\xce=\x04\x03\x03\x03i\x000f\x021\x00\xa3\x7f/\x91\xa1\xc9\xbd^\xe7\xb8b|\x16\x98\xd2U\x03\x8e\x1f\x03C\xf9[c\xa9b\x8c=9\x80\x95E\xa1\x1e\xbc\xbf.;U\xd8\xae\xeeq\xb4\xc3\xd6\xad\xf3\x021\x00\xa2\xf3\x9b\x16\x05\xb2p(\xa5\xddK\xa0i\xb5\x01ne\xb4\xfb\xde\x8f\xe0\x06\x1djS\x19\x7f\x9c\xda\xf5\xd9C\xbca\xfc+\xeb\x03\xcbo\xee\x8d#\x02\xf3\xdf\xf6Y\x02\xc30\x82\x02\xbf0\x82\x02E\xa0\x03\x02\x01\x02\x02\x11\x00\xd1\x1c\xe3FZBoY\xc5+i\x1e=\xfd\x89d0\n\x06\x08*\x86H\xce=\x04\x03\x030I1\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x0f0\r\x06\x03U\x04\n\x0c\x06Amazon1\x0c0\n\x06\x03U\x04\x0b\x0c\x03AWS1\x1b0\x19\x06\x03U\x04\x03\x0c\x12aws.nitro-enclaves0\x1e\x17\r221112090746Z\x17\r221202100745Z0d1\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x0f0\r\x06\x03U\x04\n\x0c\x06Amazon1\x0c0\n\x06\x03U\x04\x0b\x0c\x03AWS1604\x06\x03U\x04\x03\x0c-750200d365150c33.us-east-1.aws.nitro-enclaves0v0\x10\x06\x07*\x86H\xce=\x02\x01\x06\x05+\x81\x04\x00"\x03b\x00\x04\xac#it\x82\x9f\x88\x8a\x8f\x8a\xfa\x14\xa3V\x9fz\xf3\xde\x01Ty\xa4\xe6<\x04\xabj\x8b\xd77\xfe\xdc\x99\x81\xdd\x02\x8f0\x9e\x07t\x99\xc3\xbevYx\x0f8\xf9\xc1\x7f\xf2\x1cGy\xa1\x8d\x8d\xbag\x1f9\xc2\x1f\x00\x8bq\xce\x19v\x0c\r\xdf\x7f\xcd\xb3\x932>d\xb0i\x9a\xdd\xe5j=\xccW`\xad\xb7\x9euK\xa3\x81\xd50\x81\xd20\x12\x06\x03U\x1d\x13\x01\x01\xff\x04\x080\x06\x01\x01\xff\x02\x01\x020\x1f\x06\x03U\x1d#\x04\x180\x16\x80\x14\x90%\xb5\r\xd9\x05G\xe7\x96\xc3\x96\xfar\x9d\xcf\x99\xa9\xdfK\x960\x1d\x06\x03U\x1d\x0e\x04\x16\x04\x14\x11\x91\xa9\x18\x83\xb8(\x1f\x94\xfa)\x90\x92\xb3\xc5\x0f\xac\xcc\x05\xc00\x0e\x06\x03U\x1d\x0f\x01\x01\xff\x04\x04\x03\x02\x01\x860l\x06\x03U\x1d\x1f\x04e0c0a\xa0_\xa0]\x86[http://aws-nitro-enclaves-crl.s3.amazonaws.com/crl/ab4960cc-7d63-42bd-9e9f-59338cb67f84.crl0\n\x06\x08*\x86H\xce=\x04\x03\x03\x03h\x000e\x020f\x12XXrlV\xf3I\xe1V\x192\x08\xce\xf3\x9c*\x9d]\xe1\xf76\x8fKo{\x197x\xe3\x12\x83\xe9\x13\xe1\xd9\xec<A\x04\x1a\x91F\x02\xb1\xa0\xd3\x021\x00\xda\x01\x7f\x10\xb8\x1c\xc9\x86\xc9\xcb+\x81\xc1\xa4\xb7\x03X6\x9e\xe5\xbe|\x91\xe0\xcd\xe2K\xd3\n\xfb4-)\x0b#b~\xd2\xb1\xa9\xeeR3\xe8\xe8\xc9-\x99Y\x03\x180\x82\x03\x140\x82\x02\x9b\xa0\x03\x02\x01\x02\x02\x11\x00\x9a\xf8AvAX\x7ff\xe5\xe18\xb6\xc1\xfc\xd7\x960\n\x06\x08*\x86H\xce=\x04\x03\x030d1\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x0f0\r\x06\x03U\x04\n\x0c\x06Amazon1\x0c0\n\x06\x03U\x04\x0b\x0c\x03AWS1604\x06\x03U\x04\x03\x0c-750200d365150c33.us-east-1.aws.nitro-enclaves0\x1e\x17\r221114172640Z\x17\r221120112640Z0\x81\x891<0:\x06\x03U\x04\x03\x0c3203c3ddf5f3b88db.zonal.us-east-1.aws.nitro-enclaves1\x0c0\n\x06\x03U\x04\x0b\x0c\x03AWS1\x0f0\r\x06\x03U\x04\n\x0c\x06Amazon1\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x0b0\t\x06\x03U\x04\x08\x0c\x02WA1\x100\x0e\x06\x03U\x04\x07\x0c\x07Seattle0v0\x10\x06\x07*\x86H\xce=\x02\x01\x06\x05+\x81\x04\x00"\x03b\x00\x04\x92\xa0\xc7\xcc\xdf\x86\x1d\x8b\xf7\xc8cK\xc6\xb9c\x00\x9d\xef\x03l\xd5R\xd8O+\x90\xd2\x88\x04g\xca\xbcPg=\xd3M\xbf\xb7fi\xf3\x00\t\x10\x178\xac\xcd\x10=C\xde\xb0#L\x06\xf5%\xac\xb3+\xb0\x8a\xd2U\xec\x06n\xdb\xe0\xc2\xcd,\x88H\x1d\xf4sz\xb2\x02\xa4\x9f\x9cp*X\x90\x84\x9c\xdej\xf0\x88c\xa3\x81\xea0\x81\xe70\x12\x06\x03U\x1d\x13\x01\x01\xff\x04\x080\x06\x01\x01\xff\x02\x01\x010\x1f\x06\x03U\x1d#\x04\x180\x16\x80\x14\x11\x91\xa9\x18\x83\xb8(\x1f\x94\xfa)\x90\x92\xb3\xc5\x0f\xac\xcc\x05\xc00\x1d\x06\x03U\x1d\x0e\x04\x16\x04\x14\xc6\xbc\xe5\xaf\xd9\xb7\x82{*{\xf2>h(\x84z\xf7\x97\x9820\x0e\x06\x03U\x1d\x0f\x01\x01\xff\x04\x04\x03\x02\x01\x860\x81\x80\x06\x03U\x1d\x1f\x04y0w0u\xa0s\xa0q\x86ohttp://crl-us-east-1-aws-nitro-enclaves.s3.us-east-1.amazonaws.com/crl/3f4561b3-99ef-4cc4-9fd3-07969f675853.crl0\n\x06\x08*\x86H\xce=\x04\x03\x03\x03g\x000d\x020:\xb8\xa5<\x91\xa5\xb7!\x0e"\xa1\xf2\x0c\xf7\xdb\xfd\xbc\xc1\xe8^d\x1b7FT\xe2\xa7\xa9\x8c\xcd\x95b7t[-\xbc\xa1\xae\xfe\xfcy\xb6\xac[\x0b\xbb-\x020m`\x82\r\xadI\xeb^\xe2!\xcei\x18<\xf0\xe0\x8c\x01u\xa5\xeb\xc15\xd6\x18\xc65\xacG<-Q\xfe\xf5\xb7\xbc~\xf0\n.\xcb7\xeaC\x97\xd4[CY\x02\x830\x82\x02\x7f0\x82\x02\x05\xa0\x03\x02\x01\x02\x02\x15\x00\xd2\x94\x9d,\xc3?\x0c\x9e\xae\x12Tg\xfc\xff\xd7\x8d7\xfa;\xf20\n\x06\x08*\x86H\xce=\x04\x03\x030\x81\x891<0:\x06\x03U\x04\x03\x0c3203c3ddf5f3b88db.zonal.us-east-1.aws.nitro-enclaves1\x0c0\n\x06\x03U\x04\x0b\x0c\x03AWS1\x0f0\r\x06\x03U\x04\n\x0c\x06Amazon1\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x0b0\t\x06\x03U\x04\x08\x0c\x02WA1\x100\x0e\x06\x03U\x04\x07\x0c\x07Seattle0\x1e\x17\r221114220319Z\x17\r221115220319Z0\x81\x8e1\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\x08\x0c\nWashington1\x100\x0e\x06\x03U\x04\x07\x0c\x07Seattle1\x0f0\r\x06\x03U\x04\n\x0c\x06Amazon1\x0c0\n\x06\x03U\x04\x0b\x0c\x03AWS1907\x06\x03U\x04\x03\x0c0i-05a940be8fe64c488.us-east-1.aws.nitro-enclaves0v0\x10\x06\x07*\x86H\xce=\x02\x01\x06\x05+\x81\x04\x00"\x03b\x00\x04\xe0;\x1c\x15\r}\x9fo\xa3>\x08~\xc1_|\xbd\xa2\xdb\x86\xd7P#L\xe8\xe8\x9b\x07(G\x02\x12\xe2\xe60Kx\x93\xa9\xc6\x9c\xf9Q\xf1\xa9\xf8\'6\xca\x88M\r\xb8;\x8a2\xe1\xa3O\xbc\xf8\xdf\xe2\x85\xc5_q\xbc\'\xc2\xd9\xceZ\x84a@\x7f\x89t\xc1\xac\xcc\xc7\xae\x08V\xf2y\xb7D_\x01t\xc5\xddJ\xe7\xa3&0$0\x12\x06\x03U\x1d\x13\x01\x01\xff\x04\x080\x06\x01\x01\xff\x02\x01\x000\x0e\x06\x03U\x1d\x0f\x01\x01\xff\x04\x04\x03\x02\x02\x040\n\x06\x08*\x86H\xce=\x04\x03\x03\x03h\x000e\x020On\r?~\xed\xe9N\xa5\xb4\xe7-\xba\xf5\x7fo\x97\xc7\x9a\xd8\x9e7j\xcd\x89\xcf\x99E\xfd\xce\xe0\xc1B\xc2\x82\x16PnE\xe9\xd0\x84\xb1Q\xe5d\r\xfa\x021\x00\xca\x84R\xc0\r5l\xd8\'\xf92\x01J,)\xb0w\x8a\xc8Q4\x83\xb5\x8fb4\x1e\x10\xe6\xbb\x05\x00\xeep\xf4#\xe79\xc2\x1b\x117%WR\x883\xdcjpublic_keyY\x01&0\x82\x01"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x82\x01\x0f\x000\x82\x01\n\x02\x82\x01\x01\x00\xd3\x05\x80\xe5\xdf;\x9ep\xba/\xe9\x87\xcbfN \xba+\xde\xe2\x9c\xdb\x1e=\x9b\x85\xe1\xfb\x101G\xc0\r_<\xb6LV\xea\xa6\x1f\xb2\xea\x82\xberT._k\x1b\x84x\xd6\x8e\xf8\xd1<6\xdc\x857\x86\xe0\x0e\xff\x8c?\xf8C{?\xc8ri\x14\xa1.\x17\xf3\xda$!\x0bf\xa7U~}\xbal\x92\xc1\xe0\xa8\xff\xcbC\xd5\x10\x80G\x90D\xcaP\xd4\x98{\xad,\xd6\xca`\xd6\xf4\t\xa0\x91\xf4\x84\x87\'p\xb1\x8e$\xb0\x8f\xec\xe9\xa7y\xff\x16\xaf\x8c\xc6\xf0K\xe5[\xb9w\xda:\x81$\xbb0\xbcsm\xb4qhQU\xc5\x19\xd9\xf4.\xa7jp\xf1\xcb\xf2e\xcf\x9eC,\xf8\x7fEZ\x0fy`\xf9\xff\xe9,\xbe\xbe\x8c\x9e\x91\xf0\xd6\n\xe8nMI\xb7\xe7\x94A\xecII\xcf@#T\x0c\x10\x9d\x0c4$\x87\xdb%Q\x1e\x84\xde\xa4\xe0\x81-\xdfnu\xde\x81\xd14\x06\xa6/\xd7\x87\x86\xb3\x8a\xcfd\xbfs\x97\xf5c\xc9~\x06\xbb\x03:\x87$c\x02\x03\x01\x00\x01iuser_data\xf6enonce\xf6X`MZ\xa2\xf8\xdadKQ\x15)\x0b\xd6\x93e\xa9\xb5\x18\xa6\x9f9Kob\x87\xfa\x85\x04\x93\x03\x9f\x05\x8d\xdcJ\xc9\x93)\xadH\xf1\x9ec\x07~\xa2\xfe"\xc3k\x93Q%\x972\xf5|\xc3\x94\rk\x9a\xfbD\x03\xe7\x98\x98L\xdc\xd3\xe6j\x9c34WF$n:x\x89\x85\xee\x8f~y\xb0\xd6\x8c\\\x0c}\xe6\x06{'

    sig_alg, att_doc, sig = get_all_items(attdata)

    print(sig_alg)
    print(att_doc)
    print(sig)


