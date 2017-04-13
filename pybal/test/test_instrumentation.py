# -*- coding: utf-8 -*-
"""
  PyBal unit tests
  ~~~~~~~~~~~~~~~~

  This module contains tests for `pybal.instrumentation`.

"""

import mock
import json
from twisted.python.failure import Failure
from twisted.web.http import Request
from twisted.web.server import Site
from twisted.test import proto_helpers
from .fixtures import PyBalTestCase, ServerStub
from pybal.instrumentation import Resp404, ServerRoot, PoolsRoot
from pybal.instrumentation import PoolServers, PoolServer, Alerts


class WebBaseTestCase(PyBalTestCase):
    path = '/example'

    def setUp(self):
        self.request = mock.MagicMock(autospec=Request)
        self.request.uri = "http://www.example.com/test"
        self.request.path = self.path
        self.request.requestHeaders = mock.MagicMock()
        self.request.requestHeaders.hasHeader.return_value = True
        self.request.requestHeaders.getRawHeaders.return_value = 'application/json'
        self.coordinators = []
        for i in xrange(3):
            lvsservice = mock.MagicMock()
            lvsservice.name = 'test_pool%d' % i
            coord = mock.MagicMock()
            coord.servers = {}
            coord.lvsservice = lvsservice
            for j in xrange(1, 11):
                host = "mw10%02d" % j
                ip = '192.168.10.%d' % j
                port = 80
                weight = 10
                s = ServerStub(host, ip=ip, port=port, weight=weight,
                               lvsservice=lvsservice)
                s.pooled = True
                s.up = True
                coord.servers[host] = s
            self.coordinators.append(coord)
        PoolsRoot.addPool('test_pool0', self.coordinators[0])


class Resp404TestCase(WebBaseTestCase):
    """Test case for `pybal.instrumentation.Resp404`"""

    def test_init(self):
        """Test case for `Resp404.__init__`"""
        r = Resp404()
        self.assertTrue(r.isLeaf)

    def test_render(self):
        """Test case for `Resp404.render_GET`"""
        r = Resp404()
        data = json.loads(r.render_GET(self.request))
        self.assertEquals(['error'], data.keys())
        self.request.setResponseCode.assert_called_with(404)


class ServerRootTestCase(WebBaseTestCase):
    """Test case for `pybal.instrumentation.ServerRoot`"""
    path = '/'

    def test_getChild(self):
        """Test case for `ServerRoot.getChild`"""
        r = ServerRoot()
        self.assertIsInstance(r.getChild('pools', self.request), PoolsRoot)
        self.assertIsInstance(r.getChild('somethingelse', self.request),
                              Resp404)


class AlertsTestCase(WebBaseTestCase):
    """Test case for `pybal.instrumentation.Alerts`"""

    def test_render(self):
        """Test case for `PoolsRoot.render_GET`"""
        self.request.requestHeaders.getRawHeaders.return_value = 'text/http'
        crd = self.coordinators[0]
        m1 = ServerStub('mw1001')
        m2 = ServerStub('mw1002')
        m3 = ServerStub('mw1003')
        crd.servers = [m1, m2, m3]

        # Healthy pool
        crd.lvsservice.getDepoolThreshold = mock.MagicMock(return_value=0)
        r = Alerts()
        self.assertEquals("OK - All pools are healthy",
                          r.render_GET(self.request))

        # Misconfigured pool
        crd.lvsservice.getDepoolThreshold = mock.MagicMock(return_value=1.0)
        self.assertEquals('WARNING - Pool test_pool0 is too small to allow depooling. ',
                          r.render_GET(self.request))

        # Pool with too many servers down
        crd.pooledDownServers = [m1, m2]
        self.assertEquals('CRITICAL - test_pool0: Servers mw1001, mw1002 are marked down but pooled',
                          r.render_GET(self.request))


class PoolsRootTestCase(WebBaseTestCase):
    """Test case for `pybal.instrumentation.PoolsRoot`"""
    path = '/pools'

    def test_getChild(self):
        """Test case for `PoolsRoot.getChild`"""
        r = PoolsRoot()
        self.assertEquals(r, r.getChild("", self.request))
        res = r.getChild('test_pool0', self.request)
        self.assertIsInstance(res, PoolServers)
        self.assertEquals(res.coordinator, self.coordinators[0])
        notf = r.getChild('not_test', self.request)
        self.assertIsInstance(notf, Resp404)

    def test_render(self):
        """Test case for `PoolsRoot.render_GET`"""
        r = PoolsRoot()
        self.assertEquals(r.render_GET(self.request), '["test_pool0"]')


class PoolServersTestCase(WebBaseTestCase):
    """Test case for `pybal.instrumentation.PoolServers`"""
    path = '/pools/test_pool0'

    def test_getChild(self):
        """Test case for `PoolServers.getChild`"""
        r = PoolServers(self.coordinators[0])
        self.assertEquals(r, r.getChild("", self.request))
        self.assertIsInstance(r.getChild("mw2001", self.request), Resp404)
        res = r.getChild("mw1010", self.request)
        self.assertIsInstance(res, PoolServer)
        self.assertEquals(res.server.host, 'mw1010')

    def test_render(self):
        """Test case for `PoolServers.render_GET`"""
        r = PoolServers(self.coordinators[0])
        resp = json.loads(r.render_GET(self.request))
        self.assertIn('mw1009', resp)
        self.assertEquals(resp['mw1008'], {u'pooled': True, u'up': True, u'weight': 10})


class PoolServerTestCase(WebBaseTestCase):
    """Test case for `pybal.instrumentation.PoolServer`"""
    path = '/pools/test_pool0/mw1001'

    def test_render(self):
        """Test case for `PoolServer.render_GET`"""
        r = PoolServer(self.coordinators[0].servers['mw1001'])
        resp = json.loads(r.render_GET(self.request))
        self.assertEquals(resp, {u'pooled': True, u'up': True, u'weight': 10})


class SiteTest(WebBaseTestCase):

    def setUp(self):
        super(SiteTest, self).setUp()
        factory = Site(ServerRoot())
        self.proto = factory.buildProtocol(('127.0.0.1', 0))
        self.tr = proto_helpers.StringTransport()
        self.proto.makeConnection(self.tr)

    def _httpReq(self, uri='/', host='localhost', headers={}):
        data = "GET {} HTTP/1.1\r\n".format(uri)
        data +="Host: {}\r\n".format(host)
        for k, hdr in headers.items():
            data += "{}: {}".format(k, hdr)
        data += "\r\n\r\n"
        self.proto.dataReceived(data)
        hdrs, body = self.tr.value().split("\r\n\r\n")
        return (hdrs, body)

    def test_pools(self):
        """Test case for requesting the pool list"""
        _, body = self._httpReq(uri='/pools', headers={'Accept': 'application/json'})
        self.assertEquals(json.loads(body), ['test_pool0'])

    def test_404(self):
        """Test case for an non-existent base url"""
        hdr, body = self._httpReq(uri='/test')
        self.assertTrue(hdr.startswith('HTTP/1.1 404 Not Found'))
        self.assertEquals(body, 'The desired url was not found')

    def test_pool(self):
        """Test case for requesting a specific pool"""
        _, body = self._httpReq(uri='/pools/test_pool0',
                                headers={'Accept': 'application/json'})
        self.assertIn('mw1002', json.loads(body))

    def test_pool_404(self):
        """Test case for an non-existent pool"""
        hdr, _ = self._httpReq(uri='/pools/something')
        self.assertTrue(hdr.startswith('HTTP/1.1 404 Not Found'))

    def test_host(self):
        """Test case for requesting a specific host"""
        _, body = self._httpReq(uri='/pools/test_pool0/mw1001',
                                headers={'Accept': 'application/json'})
        self.assertEquals({u'pooled': True, u'up': True, u'weight': 10},
                          json.loads(body))

    def test_host_404(self):
        """Test case for an non-existent host"""
        hdr, _ = self._httpReq(uri='/pools/test_pool0/mw1011')
        self.assertTrue(hdr.startswith('HTTP/1.1 404 Not Found'))

    def test_content_type_text_plain(self):
        hdr, _ = self._httpReq(uri='/pools/test_pool0')
        self.assertTrue(hdr.startswith('HTTP/1.1 200 OK'))
        self.assertTrue("Content-Type: text/plain" in hdr)

    def test_content_type_application_json(self):
        hdr, _ = self._httpReq(uri='/pools/test_pool0',
                               headers={'Accept': 'application/json'})
        self.assertTrue(hdr.startswith('HTTP/1.1 200 OK'))
        self.assertTrue("Content-Type: application/json" in hdr)

    def tearDown(self):
        self.proto.connectionLost(Failure(TypeError("whatever")))
