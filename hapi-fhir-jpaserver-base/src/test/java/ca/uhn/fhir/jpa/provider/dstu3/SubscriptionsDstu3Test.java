package ca.uhn.fhir.jpa.provider.dstu3;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import org.eclipse.jetty.websocket.api.Session;
import org.eclipse.jetty.websocket.api.annotations.OnWebSocketConnect;
import org.eclipse.jetty.websocket.api.annotations.OnWebSocketMessage;
import org.eclipse.jetty.websocket.api.annotations.WebSocket;
import org.eclipse.jetty.websocket.client.ClientUpgradeRequest;
import org.eclipse.jetty.websocket.client.WebSocketClient;
import org.hl7.fhir.dstu3.model.Observation;
import org.hl7.fhir.dstu3.model.Patient;
import org.hl7.fhir.dstu3.model.Subscription;
import org.hl7.fhir.dstu3.model.Observation.ObservationStatus;
import org.hl7.fhir.dstu3.model.Subscription.SubscriptionChannelType;
import org.hl7.fhir.dstu3.model.Subscription.SubscriptionStatus;
import org.hl7.fhir.instance.model.api.IBaseResource;
import org.hl7.fhir.instance.model.api.IIdType;
import org.junit.Before;
import org.junit.Test;

import ca.uhn.fhir.jpa.util.SubscriptionsRequireManualActivationInterceptorDstu3;
import ca.uhn.fhir.model.primitive.IdDt;
import ca.uhn.fhir.rest.server.EncodingEnum;
import ca.uhn.fhir.rest.server.exceptions.UnprocessableEntityException;
import ca.uhn.fhir.rest.server.servlet.ServletRequestDetails;

public class SubscriptionsDstu3Test extends BaseResourceProviderDstu3Test {

	private static final String WEBSOCKET_PATH = "/websocket/dstu3";

	public class BaseSocket {
		protected String myError;
		protected boolean myGotBound;
		protected int myPingCount;
		protected String mySubsId;

	}

	private static final org.slf4j.Logger ourLog = org.slf4j.LoggerFactory.getLogger(SubscriptionsDstu3Test.class);

	@Before
	public void beforeEnableScheduling() {
		myDaoConfig.setSchedulingDisabled(false);
	}

	@Override
	public void beforeCreateInterceptor() {
		super.beforeCreateInterceptor();

		SubscriptionsRequireManualActivationInterceptorDstu3 interceptor = new SubscriptionsRequireManualActivationInterceptorDstu3();
		interceptor.setDao(mySubscriptionDao);
		myDaoConfig.getInterceptors().add(interceptor);
	}

	private void sleepUntilPingCount(BaseSocket socket, int wantPingCount) throws InterruptedException {
		ourLog.info("Entering loop");
		for (long start = System.currentTimeMillis(), now = System.currentTimeMillis(); now - start <= 20000; now = System.currentTimeMillis()) {
			ourLog.debug("Starting");
			if (socket.myError != null) {
				fail(socket.myError);
			}
			if (socket.myPingCount >= wantPingCount) {
				ourLog.info("Breaking loop");
				break;
			}
			ourLog.debug("Sleeping");
			Thread.sleep(100);
		}

		ourLog.info("Out of loop, pingcount {} error {}", socket.myPingCount, socket.myError);

		assertNull(socket.myError, socket.myError);
		assertEquals(wantPingCount, socket.myPingCount);
	}

	@Test
	public void testCreateInvalidNoStatus() {
		Subscription subs = new Subscription();
		subs.getChannel().setType(SubscriptionChannelType.RESTHOOK);
		subs.setCriteria("Observation?identifier=123");
		try {
			ourClient.create().resource(subs).execute();
			fail();
		} catch (UnprocessableEntityException e) {
			assertEquals("HTTP 422 Unprocessable Entity: Can not create resource: Subscription.status must be populated", e.getMessage());
		}

		subs.setId("ABC");
		try {
			ourClient.update().resource(subs).execute();
			fail();
		} catch (UnprocessableEntityException e) {
			assertEquals("HTTP 422 Unprocessable Entity: Can not create resource: Subscription.status must be populated", e.getMessage());
		}

		subs.setStatus(SubscriptionStatus.REQUESTED);
		ourClient.update().resource(subs).execute();
	}

	@Test
	public void testUpdateToInvalidStatus() {
		Subscription subs = new Subscription();
		subs.getChannel().setType(SubscriptionChannelType.RESTHOOK);
		subs.setCriteria("Observation?identifier=123");
		subs.setStatus(SubscriptionStatus.REQUESTED);
		IIdType id = ourClient.create().resource(subs).execute().getId();
		subs.setId(id);

		try {
			subs.setStatus(SubscriptionStatus.ACTIVE);
			ourClient.update().resource(subs).execute();
			fail();
		} catch (UnprocessableEntityException e) {
			assertEquals("HTTP 422 Unprocessable Entity: Subscription.status can not be changed from 'requested' to 'active'", e.getMessage());
		}

		try {
			subs.setStatus((SubscriptionStatus) null);
			ourClient.update().resource(subs).execute();
			fail();
		} catch (UnprocessableEntityException e) {
			assertEquals("HTTP 422 Unprocessable Entity: Can not update resource: Subscription.status must be populated", e.getMessage());
		}

		subs.setStatus(SubscriptionStatus.OFF);
		ourClient.update().resource(subs).execute();
	}


	@Test
	public void testCreateInvalidWrongStatus() {
		Subscription subs = new Subscription();
		subs.getChannel().setType(SubscriptionChannelType.RESTHOOK);
		subs.setStatus(SubscriptionStatus.ACTIVE);
		subs.setCriteria("Observation?identifier=123");
		try {
			ourClient.create().resource(subs).execute();
			fail();
		} catch (UnprocessableEntityException e) {
			assertEquals("HTTP 422 Unprocessable Entity: Subscription.status must be 'off' or 'requested' on a newly created subscription", e.getMessage());
		}

		subs.setId("ABC");
		try {
			ourClient.update().resource(subs).execute();
			fail();
		} catch (UnprocessableEntityException e) {
			assertEquals("HTTP 422 Unprocessable Entity: Subscription.status must be 'off' or 'requested' on a newly created subscription", e.getMessage());
		}
	}

	@Test
	public void testSubscriptionDynamic() throws Exception {
		myDaoConfig.setSubscriptionEnabled(true);
		myDaoConfig.setSubscriptionPollDelay(0);

		String methodName = "testSubscriptionDynamic";
		Patient p = new Patient();
		p.addName().addFamily(methodName);
		IIdType pId = myPatientDao.create(p, new ServletRequestDetails()).getId().toUnqualifiedVersionless();

		String criteria = "Observation?subject=Patient/" + pId.getIdPart();
		DynamicEchoSocket socket = new DynamicEchoSocket(criteria, EncodingEnum.JSON);
		WebSocketClient client = new WebSocketClient();
		try {
			client.start();
			URI echoUri = new URI("ws://localhost:" + ourPort + WEBSOCKET_PATH);
			client.connect(socket, echoUri, new ClientUpgradeRequest());
			ourLog.info("Connecting to : {}", echoUri);

			sleepUntilPingCount(socket, 1);

			mySubscriptionDao.read(new IdDt("Subscription", socket.mySubsId), new ServletRequestDetails());

			Observation obs = new Observation();
			obs.getSubject().setReferenceElement(pId);
			obs.setStatus(ObservationStatus.FINAL);
			IIdType afterId1 = myObservationDao.create(obs, new ServletRequestDetails()).getId().toUnqualifiedVersionless();

			obs = new Observation();
			obs.getSubject().setReferenceElement(pId);
			obs.setStatus(ObservationStatus.FINAL);
			IIdType afterId2 = myObservationDao.create(obs, new ServletRequestDetails()).getId().toUnqualifiedVersionless();

			Thread.sleep(100);

			sleepUntilPingCount(socket, 3);

			obs = (Observation) socket.myReceived.get(0);
			assertEquals(afterId1.getValue(), obs.getIdElement().toUnqualifiedVersionless().getValue());

			obs = (Observation) socket.myReceived.get(1);
			assertEquals(afterId2.getValue(), obs.getIdElement().toUnqualifiedVersionless().getValue());

			obs = new Observation();
			obs.getSubject().setReferenceElement(pId);
			obs.setStatus(ObservationStatus.FINAL);
			IIdType afterId3 = myObservationDao.create(obs, new ServletRequestDetails()).getId().toUnqualifiedVersionless();

			sleepUntilPingCount(socket, 4);

			obs = (Observation) socket.myReceived.get(2);
			assertEquals(afterId3.getValue(), obs.getIdElement().toUnqualifiedVersionless().getValue());

		} finally {
			try {
				client.stop();
			} catch (Exception e) {
				ourLog.error("Failure", e);
				fail(e.getMessage());
			}
		}

	}

	
	@Test
	public void testSubscriptionDynamicXml() throws Exception {
		myDaoConfig.setSubscriptionEnabled(true);
		myDaoConfig.setSubscriptionPollDelay(0);

		String methodName = "testSubscriptionDynamic";
		Patient p = new Patient();
		p.addName().addFamily(methodName);
		IIdType pId = myPatientDao.create(p, new ServletRequestDetails()).getId().toUnqualifiedVersionless();

		String criteria = "Observation?subject=Patient/" + pId.getIdPart() + "&_format=xml";
		DynamicEchoSocket socket = new DynamicEchoSocket(criteria, EncodingEnum.XML);
		WebSocketClient client = new WebSocketClient();
		try {
			client.start();
			URI echoUri = new URI("ws://localhost:" + ourPort + WEBSOCKET_PATH);
			client.connect(socket, echoUri, new ClientUpgradeRequest());
			ourLog.info("Connecting to : {}", echoUri);

			sleepUntilPingCount(socket, 1);

			mySubscriptionDao.read(new IdDt("Subscription", socket.mySubsId), new ServletRequestDetails());

			Observation obs = new Observation();
			obs.getMeta().addProfile("http://foo");
			obs.getSubject().setReferenceElement(pId);
			obs.setStatus(ObservationStatus.FINAL);
			IIdType afterId1 = myObservationDao.create(obs, new ServletRequestDetails()).getId().toUnqualifiedVersionless();

			obs = new Observation();
			obs.getSubject().setReferenceElement(pId);
			obs.setStatus(ObservationStatus.FINAL);
			IIdType afterId2 = myObservationDao.create(obs, new ServletRequestDetails()).getId().toUnqualifiedVersionless();

			Thread.sleep(100);

			sleepUntilPingCount(socket, 3);

			obs = (Observation) socket.myReceived.get(0);
			assertEquals(afterId1.getValue(), obs.getIdElement().toUnqualifiedVersionless().getValue());

			obs = (Observation) socket.myReceived.get(1);
			assertEquals(afterId2.getValue(), obs.getIdElement().toUnqualifiedVersionless().getValue());

			obs = new Observation();
			obs.getSubject().setReferenceElement(pId);
			obs.setStatus(ObservationStatus.FINAL);
			IIdType afterId3 = myObservationDao.create(obs, new ServletRequestDetails()).getId().toUnqualifiedVersionless();

			sleepUntilPingCount(socket, 4);

			obs = (Observation) socket.myReceived.get(2);
			assertEquals(afterId3.getValue(), obs.getIdElement().toUnqualifiedVersionless().getValue());

		} finally {
			try {
				client.stop();
			} catch (Exception e) {
				ourLog.error("Failure", e);
				fail(e.getMessage());
			}
		}

	}
	
	@Test
	public void testSubscriptionSimple() throws Exception {
		myDaoConfig.setSubscriptionEnabled(true);
		myDaoConfig.setSubscriptionPollDelay(0);

		String methodName = "testSubscriptionResourcesAppear";
		Patient p = new Patient();
		p.addName().addFamily(methodName);
		IIdType pId = myPatientDao.create(p, new ServletRequestDetails()).getId().toUnqualifiedVersionless();

		Subscription subs = new Subscription();
		subs.getMeta().addProfile("http://foo");
		subs.getChannel().setType(SubscriptionChannelType.WEBSOCKET);
		subs.setCriteria("Observation?subject=Patient/" + pId.getIdPart());
		subs.setStatus(SubscriptionStatus.ACTIVE);
		String subsId = mySubscriptionDao.create(subs, new ServletRequestDetails()).getId().getIdPart();

		Thread.sleep(100);

		Observation obs = new Observation();
		obs.getSubject().setReferenceElement(pId);
		obs.setStatus(ObservationStatus.FINAL);
		IIdType afterId1 = myObservationDao.create(obs, new ServletRequestDetails()).getId().toUnqualifiedVersionless();

		obs = new Observation();
		obs.getSubject().setReferenceElement(pId);
		obs.setStatus(ObservationStatus.FINAL);
		IIdType afterId2 = myObservationDao.create(obs, new ServletRequestDetails()).getId().toUnqualifiedVersionless();

		Thread.sleep(100);

		WebSocketClient client = new WebSocketClient();
		SimpleEchoSocket socket = new SimpleEchoSocket(subsId);
		try {
			client.start();
			URI echoUri = new URI("ws://localhost:" + ourPort + WEBSOCKET_PATH);
			ClientUpgradeRequest request = new ClientUpgradeRequest();
			client.connect(socket, echoUri, request);
			ourLog.info("Connecting to : {}", echoUri);

			sleepUntilPingCount(socket, 1);

			obs = new Observation();
			obs.getSubject().setReferenceElement(pId);
			obs.setStatus(ObservationStatus.FINAL);
			IIdType afterId3 = myObservationDao.create(obs, new ServletRequestDetails()).getId().toUnqualifiedVersionless();

			sleepUntilPingCount(socket, 2);

		} finally {
			try {
				client.stop();
			} catch (Exception e) {
				ourLog.error("Failure", e);
				fail(e.getMessage());
			}
		}

	}

	@Test
	public void testUpdateFails() {
		Subscription subs = new Subscription();
		subs.getChannel().setType(SubscriptionChannelType.RESTHOOK);
		subs.setStatus(SubscriptionStatus.REQUESTED);
		subs.setCriteria("Observation?identifier=123");
		IIdType id = ourClient.create().resource(subs).execute().getId().toUnqualifiedVersionless();

		subs.setId(id);

		try {
			subs.setStatus(SubscriptionStatus.ACTIVE);
			ourClient.update().resource(subs).execute();
			fail();
		} catch (UnprocessableEntityException e) {
			assertEquals("HTTP 422 Unprocessable Entity: Subscription.status can not be changed from 'requested' to 'active'", e.getMessage());
		}

		try {
			subs.setStatus((SubscriptionStatus) null);
			ourClient.update().resource(subs).execute();
			fail();
		} catch (UnprocessableEntityException e) {
			assertEquals("HTTP 422 Unprocessable Entity: Can not update resource: Subscription.status must be populated", e.getMessage());
		}

		subs.setStatus(SubscriptionStatus.OFF);
	}

	/**
	 * Basic Echo Client Socket
	 */
	@WebSocket(maxTextMessageSize = 64 * 1024)
	public class SimpleEchoSocket extends BaseSocket {

		@SuppressWarnings("unused")
		private Session session;

		public SimpleEchoSocket(String theSubsId) {
			mySubsId = theSubsId;
		}

		@OnWebSocketConnect
		public void onConnect(Session session) {
			ourLog.info("Got connect: {}", session);
			this.session = session;
			try {
				String sending = "bind " + mySubsId;
				ourLog.info("Sending: {}", sending);
				session.getRemote().sendString(sending);
			} catch (Throwable t) {
				ourLog.error("Failure", t);
			}
		}

		@OnWebSocketMessage
		public void onMessage(String theMsg) {
			ourLog.info("Got msg: {}", theMsg);
			if (theMsg.equals("bound " + mySubsId)) {
				myGotBound = true;
			} else if (myGotBound && theMsg.startsWith("ping " + mySubsId)) {
				myPingCount++;
			} else {
				myError = "Unexpected message: " + theMsg;
			}
		}
	}

	/**
	 * Basic Echo Client Socket
	 */
	@WebSocket(maxTextMessageSize = 64 * 1024)
	public class DynamicEchoSocket extends BaseSocket {

		private List<IBaseResource> myReceived = new ArrayList<IBaseResource>();
		@SuppressWarnings("unused")
		private Session session;
		private String myCriteria;
		private EncodingEnum myEncoding;

		public DynamicEchoSocket(String theCriteria, EncodingEnum theEncoding) {
			myCriteria = theCriteria;
			myEncoding = theEncoding;
		}

		@OnWebSocketConnect
		public void onConnect(Session session) {
			ourLog.info("Got connect: {}", session);
			this.session = session;
			try {
				String sending = "bind " + myCriteria;
				ourLog.info("Sending: {}", sending);
				session.getRemote().sendString(sending);
			} catch (Throwable t) {
				ourLog.error("Failure", t);
			}
		}

		@OnWebSocketMessage
		public void onMessage(String theMsg) {
			ourLog.info("Got msg: {}", theMsg);
			if (theMsg.startsWith("bound ")) {
				myGotBound = true;
				mySubsId = (theMsg.substring("bound ".length()));
				myPingCount++;
			} else if (myGotBound && theMsg.startsWith("add " + mySubsId + "\n")) {
				String text = theMsg.substring(("add " + mySubsId + "\n").length());
				IBaseResource res = myEncoding.newParser(myFhirCtx).parseResource(text);
				myReceived.add(res);
				myPingCount++;
			} else {
				myError = "Unexpected message: " + theMsg;
			}
		}
	}
}
