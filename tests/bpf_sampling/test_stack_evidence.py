"""The ELF gate must not use another process to satisfy target stack evidence."""
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zlib
import stack_evidence


class StackEvidenceIdentityTests(unittest.TestCase):
    def fixture(self, directory, foreign_kernel=False, foreign_user=False):
        symbols = {}
        records = []
        for letter, address in [('a',0x1000),('b',0x2000)]:
            symbols.update({f'sample_loop_{letter}':address, f'sample_loop_{letter}_end':address+16,
                            f'sample_middle_{letter}_return':address+0x100, f'sample_chain_{letter}_return':address+0x200})
            records.extend([(address+4,2,[address+4,address+0x100,address+0x200],4,foreign_user)]*2)
        records.extend([(0xffff1004,1,[0xffff1004,0xffff2004,0xffff3004],4,foreign_kernel)]*2)
        for index,(name,status) in enumerate([('zero',1),('unmapped',4),('cycle',3),('badra',5),('misaligned',2),('deep',6)]):
            address=0x3000+index*0x100
            symbols[f'sample_probe_{name}_start']=address
            symbols[f'sample_probe_{name}_end']=address+16
            records.append((address+4,2,[address+4],status,False))
        records.extend([(0x8004,2,[0x8004],1,False)]*(16-len(records)))
        raw=bytearray()
        for sequence,(ip,mode,ips,status,foreign) in enumerate(records):
            context=bytearray(640)
            struct.pack_into('<QQQIIIIQQII',context,0,10_000_000,0,200+sequence,0,41 if foreign else 40,42 if foreign else 41,0,99,ip,mode,2)
            struct.pack_into('<QQQQQHHHHIIQ',context,64,sequence+1,0x10000,0x10010,0,5,3,32,len(ips),status,16*(len(ips)-1),512,0)
            struct.pack_into(f'<{len(ips)}Q',context,128,*ips)
            frame=struct.pack('<IHHI',9,0,656,640)+context+bytes(4)
            raw.extend(struct.pack('<QIIII',sequence,0,len(frame),zlib.crc32(frame),0)+frame)
        (directory/'records.pbraw').write_bytes(struct.pack('<8sQQQQII16x',b'PBRW0001',100,300,len(records),len(raw),zlib.crc32(raw),0)+raw)
        # ELF parsing itself is independently performed against deployed files;
        # this test supplies known symbol tables to isolate attribution policy.
        (directory/'payload.elf').write_bytes(b'payload fixture')
        (directory/'kernel.elf').write_bytes(b'kernel fixture')
        (directory/'inputs.json').write_text(json.dumps({'mode':'cpu','context_format':'software-stack-v3','kernel_elf_matches_boot':True,
            'payload_sha256':hashlib.sha256((directory/'payload.elf').read_bytes()).hexdigest(),
            'kernel_elf_sha256':hashlib.sha256((directory/'kernel.elf').read_bytes()).hexdigest()}))
        (directory/'archive.json').write_text(json.dumps({'stack_target':{'pid':40,'tid':41},'snapshots':{'before':{'pid':40},'after':{'pid':40}}}))
        kernel=[(0xffff1000,0xffff1100,'allocate_page'),(0xffff2000,0xffff2100,'sys_mmap'),(0xffff3000,0xffff3100,'syscall_handler')]
        return lambda path: (symbols,[(0x1000,0x9000,'payload')]) if path.name=='payload.elf' else ({},kernel)

    def test_target_known_chains_and_all_source_instances_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            directory=Path(temp)
            resolver=self.fixture(directory)
            with patch.object(stack_evidence,'elf_symbols',side_effect=resolver):
                result=stack_evidence.verify(directory)
            self.assertEqual(result['counts']['kernel_mmap'],2)
            self.assertEqual(result['target'],{'pid':40,'tid':41})
            self.assertEqual(len(result['source_counts']),16)

    def test_foreign_process_kernel_mmap_cannot_satisfy_target_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            directory=Path(temp)
            resolver=self.fixture(directory,foreign_kernel=True)
            with patch.object(stack_evidence,'elf_symbols',side_effect=resolver), self.assertRaisesRegex(ValueError,'kernel_mmap.*0'):
                stack_evidence.verify(directory)

    def test_matching_user_addresses_from_another_process_cannot_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            directory=Path(temp)
            resolver=self.fixture(directory,foreign_user=True)
            with patch.object(stack_evidence,'elf_symbols',side_effect=resolver), self.assertRaisesRegex(ValueError,'user_a.*0'):
                stack_evidence.verify(directory)
