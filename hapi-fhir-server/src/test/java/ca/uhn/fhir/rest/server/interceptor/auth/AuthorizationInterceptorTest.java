package ca.uhn.fhir.rest.server.interceptor.auth;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.interceptor.api.Pointcut;
import ca.uhn.fhir.model.api.IFhirVersion;
import ca.uhn.fhir.model.primitive.IdDt;
import ca.uhn.fhir.rest.api.RestOperationTypeEnum;
import ca.uhn.fhir.rest.api.server.RequestDetails;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoSettings;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@MockitoSettings
class AuthorizationInterceptorTest  {
	// private static final Logger ourLog = LoggerFactory.getLogger(AuthorizationInterceptorTest.class);

	@Mock
	RequestDetails myRequestDetails;

	@Mock
	private FhirContext myFhirContext;

	@Mock
	private IFhirVersion myFhirVersion;


	@Test
	void testDenyPatientCompartmentResourceWithNoProactiveBlocking() {

		AuthorizationInterceptor interceptor = new AuthorizationInterceptor() {
			@Override
			public List<IAuthRule> buildRuleList(RequestDetails theRequestDetails) {
				return new RuleBuilder()
						.deny("deny group").read().resourcesOfType("Group").withAnyId().andThen()
						.allow("allow patient compartment").read().allResources().inCompartment("Patient", new IdDt("Patient/1"))
						.build();
			}
		};

		// mimic a search to /Patient when a SearchNarrowingIntercetor is in play and has added /Patient?_id=Patient/1
		when(myRequestDetails.getRestOperationType()).thenReturn(RestOperationTypeEnum.SEARCH_TYPE);
		when(myRequestDetails.getResourceName()).thenReturn("Patient");
		when(myRequestDetails.getFhirContext()).thenReturn(myFhirContext);

		Map<String, String[]> params = new HashMap<>();
		params.put("_id", new String[] { "Patient/1" });
		when(myRequestDetails.getParameters()).thenReturn(params);

		when(myFhirContext.getVersion()).thenReturn(myFhirVersion);
		when(myFhirVersion.newIdType()).thenReturn(new IdDt());

		// when DO_NOT_PROACTIVELY_BLOCK_COMPARTMENT_READ_ACCESS is set, the Intercetor fails to determine
		// the request is to Patient, and applies the DENY rule on Group to it throwing an
		interceptor.setFlags(AuthorizationFlagsEnum.DO_NOT_PROACTIVELY_BLOCK_COMPARTMENT_READ_ACCESS);

		// this request throws a ForbiddenOperationException - it should not
		Assertions.assertDoesNotThrow(() -> interceptor.incomingRequestPreHandled(myRequestDetails, Pointcut.SERVER_INCOMING_REQUEST_PRE_HANDLED));

	}

	@Test
	void testDenyPatientCompartmentResourceWithProactiveBlocking() {

		AuthorizationInterceptor interceptor = new AuthorizationInterceptor() {
			@Override
			public List<IAuthRule> buildRuleList(RequestDetails theRequestDetails) {
				return new RuleBuilder()
						.deny("deny group").read().resourcesOfType("Group").withAnyId().andThen()
						.allow("allow patient compartment").read().allResources().inCompartment("Patient", new IdDt("Patient/1"))
						.build();
			}
		};

		// mimic a search to /Patient when a SearchNarrowingIntercetor is in play and has added /Patient?_id=Patient/1
		when(myRequestDetails.getRestOperationType()).thenReturn(RestOperationTypeEnum.SEARCH_TYPE);
		when(myRequestDetails.getResourceName()).thenReturn("Patient");
		when(myRequestDetails.getFhirContext()).thenReturn(myFhirContext);
		Map<String, String[]> params = new HashMap<>();
		params.put("_id", new String[] { "Patient/1" });
		when(myRequestDetails.getParameters()).thenReturn(params);

		when(myFhirContext.getVersion()).thenReturn(myFhirVersion);
		when(myFhirVersion.newIdType()).thenReturn(new IdDt());

		// when DO_NOT_PROACTIVELY_BLOCK_COMPARTMENT_READ_ACCESS is not set, the request correctly detects
		// the DENY rule does not apply to the requestes resource
		// interceptor.setFlags(AuthorizationFlagsEnum.DO_NOT_PROACTIVELY_BLOCK_COMPARTMENT_READ_ACCESS);
		Assertions.assertDoesNotThrow(() -> interceptor.incomingRequestPreHandled(myRequestDetails, Pointcut.SERVER_INCOMING_REQUEST_PRE_HANDLED));
	}
}
