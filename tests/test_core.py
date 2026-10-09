import unittest, uuid
from pathlib import Path
import server

class CoreTests(unittest.TestCase):
    def setUp(self):
        server.DB=Path(__file__).parent.parent/f'.test-{uuid.uuid4().hex}.db'; server.init_db()
    def tearDown(self):
        db=server.DB
        for suffix in ('','-wal','-shm'):
            try: Path(str(db)+suffix).unlink()
            except FileNotFoundError: pass
    def test_normalize_utc_and_validation(self):
        e=server.normalize({'timestamp':'2026-10-08T10:00:00+02:00','src_ip':'10.0.0.1','dst_ip':'203.0.113.5','dst_port':'443'})
        self.assertEqual(e['timestamp'],'2026-10-08T08:00:00Z');self.assertEqual(e['dst_port'],443)
        with self.assertRaises(ValueError): server.normalize({'src_ip':'x','dst_ip':'y'})
    def test_seed_derived_findings_graph_replay_order(self):
        self.assertEqual(server.overview()['events'],12)
        self.assertTrue(server.findings('inc-demo-001'))
        data=server.events('inc-demo-001');self.assertEqual(data,sorted(data,key=lambda x:x['timestamp']))
        graph=server.graph('inc-demo-001');self.assertGreaterEqual(len(graph['nodes']),4);self.assertTrue(graph['edges'])
    def test_reseed_is_idempotent(self):
        with server.connect() as db: server.seed(db)
        self.assertEqual(server.overview()['events'],12)
    def test_upload_parser_sample_formats_and_rejections(self):
        row={'timestamp':'2026-10-08T00:00:00Z','src_ip':'10.0.0.1','dst_ip':'10.0.0.2'}
        self.assertEqual(server.normalize(row)['protocol'],'UNKNOWN')
        with self.assertRaises(ValueError): server.normalize(row|{'dst_port':99999})

if __name__=='__main__': unittest.main()
