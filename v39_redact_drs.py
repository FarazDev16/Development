from uuid import UUID

from flows_sdk.flows import Flow
from flows_sdk.implementations.idp_v39 import idp_blocks
from flows_sdk.implementations.idp_v39.idp_blocks import IDPCoreBlock
from flows_sdk.package_utils import export_flow


from flows_sdk.flows import Flow, Parameter
from flows_sdk.types import HsBlockInstance, StoreBlobRequest
from flows_sdk.blocks import Block, CodeBlock, PythonBlock, Routing
from flows_sdk.utils import workflow_input

from typing import Any, Dict, List, Optional
from uuid import UUID

from flows_sdk.implementations.idp_v39.idp_blocks import (
    IdpCustomSupervisionBlock,
    IDPFullPageTranscriptionBlock,
    IDPOutputsBlock,
    MachineClassificationBlock,
    MachineCollationBlock,
    MachineIdentificationBlock,
    MachineTranscriptionBlock,
    ManualClassificationBlock,
    ManualIdentificationBlock,
    ManualTranscriptionBlock,
    SubmissionBootstrapBlock,
    SubmissionCompleteBlock,
)
from flows_sdk.implementations.idp_v39.additional_blocks import HttpRestBlock, EntityRecognitionBlock
from flows_sdk.implementations.idp_v39.idp_values import (
    IDPCoreManifest,
    IDPTriggers,
    IdpWorkflowConfig,
    get_idp_wf_config,
    get_idp_wf_inputs,
)

IDP_TASK_NAME = 'R39_REDACTION_MASTER_FLOW'
IDP_UUID = 'b0c21da2-7257-4929-bcdd-50aeaee3f94a'
# Regex a nd Keyword map for Custom Entity Detection
DEFAULT_PII_REGEX_MAP = {
    'employer id': 'default',
    'ssn': 'default',
    'email': 'default',
    'us phone number': 'default',
    'date': 'default',
    'micr': 'default',
    'machine readable line': 'default',
    'address': 'default'
}

DEFAULT_PII_KEYWORD_MAP = {
    'policy number': ['default'],
    'loan number': ['default'],
    'credit card number': ['default'],
    'customer id': ['default'],
    'account number': ['default'],
    'employee id': ['default'],
    'employer id': ['default'],
    'ssn': ['default'],
    'email': ['default'],
    'us phone number': ['default'],
    'date': ['default'],
    'passport number': ['default'],
    'uscis number': ['default'],
    'driver license number': ['default'],
    'i94 number': ['default'],
    'pin number': ['default'],
    'micr': ['default'],
    'ptin number': ['default'],
    'judgment number': ['default'],
    'case number': ['default'],
    'bankruptcy number': ['default'],
    'application number': ['default'],
    'file number': ['default'],
    'routing number': ['default'],
    'nmls number': ['default'],
    'appraiser certification number': ['default'],
    'driver license restrictions': ['default'],
    'address': ['default']
}
class EntityRecognitionBlock(Block):
    def __init__(self, pages: Any,regex_map: Any,keyword_map: Any, reference_name: Optional[str] = None):
        super().__init__(
            identifier='EntityRecognition',
            reference_name=reference_name,
            input={
                'pages': pages,
                'regex_map': regex_map,
                'keyword_map': keyword_map,
            },
            title='Entity Recognition',
            description='Recognizes names, addresses,  organization names and custum entities.',
        )

class CustomParams:
    SendRequiredFieldsToSupervisionIfBlank: str = 'send_required_fields_to_supervision_if_blank'
    ShouldExecuteFPT: str = 'should_execute_fpt'
    ShouldExecuteER: str = 'should_execute_er'
    ShouldRedactER: str = 'should_redact_er'
    ShouldRedactLayoutFields: str = 'should_redact_layout_fields'
    RedactLayoutFields: str = 'redact_layout_fields'
    ShouldRedactLayoutFieldsOutputName: str = 'redact_layout_fields_output_name'
    DrspayloadReceiverOauth2AuthorizationUrl: str = 'DrspayloadReceiverOauth2AuthorizationUrl'
    DrspayloadReceiverClientId: str = 'DrspayloadReceiverClientId'
    DrspayloadReceiverClientSecret: str = 'DrspayloadReceiverClientSecret'
    DrspayloadReceiverEndpointUrl: str = 'DrspayloadReceiverEndpointUrl'
    ShouldExecuteSendPayload: str = 'should_execute_send_payload'
    DrsScopeSendPayload: str = 'DrsScopeSendPayload'


def idp_workflow() -> Flow:

     # Define IDP manifest and append workflow parameters to its input
    manifest: IDPCoreManifest = IDPCoreManifest(flow_identifier=IDP_TASK_NAME)

    '''
    Option to add global parameters to the Flow Settings. 
    Examples provided below which are inherited from the class that was created towards the top of this code
    '''
    wf_params: List[Parameter] = [
        Parameter(
            name='regex_map',
            type='object',
            title='Regex map',
            value=DEFAULT_PII_REGEX_MAP,
            json_schema={'type': 'object'},
        ),
        Parameter(
            name='keyword_map',
            type='object',
            title='Keyword map',
            value=DEFAULT_PII_KEYWORD_MAP,
            json_schema={'type': 'object'},
        ),
        Parameter(
            name=CustomParams.SendRequiredFieldsToSupervisionIfBlank,
            type='boolean',
            title='Send Required Fields That Are Blank To Supervision?',
            ui={'hidden': False},
            description='Sends required fields to manual transcription if they are blank',
            value=False,
            optional=False,
        ),
        Parameter(
            name=CustomParams.ShouldExecuteFPT,
            type='boolean',
            title='Perform FPT On Unassigned Pages, or Redact Fields in Layouts?',
            ui={'hidden': False},
            description='Check this box if you want to perform Full Page Transcription on Unassigned Pages, or Redact Fields in Layouts',
            value=False,
            optional=False,
        ),
        Parameter(
            name=CustomParams.ShouldExecuteER,
            type='boolean',
            title='Perform ER On Unassigned Pages?',
            ui={'hidden': False},
            description='Check this box if you want to perform Named Entity Recognition on Unassigned Pages',
            value=False,
            dependencies=[
                {
                    'condition': {'properties': {'should_execute_fpt': {'const': False}}},
                    'override': {'ui': {'na_reason': 'Not applied when Perform FPT on Unassigned Pages is unchecked'}},
                }
            ],
            optional=False,
        ),
        Parameter(
            name=CustomParams.ShouldRedactER,
            type='boolean',
            title='Perform redaction on ER output?',
            description='Check this box if you want to perform redaction on ER output',
            value=False,
            dependencies=[
                {
                    'condition': {'properties': {'should_execute_er': {'const': False}}},
                    'override': {'ui': {'na_reason': 'Not applied when Perform ER on Unassigned Pages is unchecked'}},
                }
            ],
        ),
        Parameter(
            name=CustomParams.ShouldRedactLayoutFields,
            type='boolean',
            title='Perform redaction of named fields in layouts?',
            ui={'hidden': False},
            description='Check this box if you want to redact certain fields in your layout',
            value=False,
            dependencies=[
                {
                    'condition': {'properties': {'should_execute_fpt': {'const': False}}},
                    'override': {'ui': {'na_reason': 'Not applied when Perform FPT on Unassigned Pages is unchecked'}},
                }
            ],
            optional=False,
        ),
        Parameter(
            name=CustomParams.RedactLayoutFields,
            type='text',
            title='Layout field names to be redacted',
            description='Separate each layout field name to be redacted by a comma',
            value='',
            optional=False,
            dependencies=[
                {
                    'condition': {'properties': {'should_redact_layout_fields': {'const': False}}},
                    'override': {'ui': {'na_reason': 'Not applied when Perform FPT on Unassigned Pages is unchecked'}},
                }
            ],
        ),

        Parameter(
            name=CustomParams.ShouldRedactLayoutFieldsOutputName,
            type='boolean',
            title='Perform redaction of fields in layouts that are marked with REDACT_ in the output name?',
            ui={'hidden': False},
            description='Check this box if you want to redact certain fields in your layout',
            value=False,
            dependencies=[
                {
                    'condition': {'properties': {'should_execute_fpt': {'const': False}}},
                    'override': {'ui': {'na_reason': 'Not applied when Perform FPT on Unassigned Pages is unchecked'}},
                }
            ],
            optional=False,
        ),
        Parameter(            
            name=CustomParams.DrspayloadReceiverOauth2AuthorizationUrl,
            type='string',
            title='OAuth2 Authorization URL',
            ui={'hidden': False},
            description='The URL for the OAuth2 authorization endpoint',
            value='',  # Default value or leave empty
            optional=False,
            secret=False
        ),
        Parameter(
            name=CustomParams.DrspayloadReceiverClientId,
            type='string',
            title='Client ID',
            description='The client ID for OAuth2 authentication.',
            ui={'hidden': False},
            value='',
            optional=False,
            secret=False
        ),
        Parameter(
            name=CustomParams.DrspayloadReceiverClientSecret,
            type='string',
            title='Client Secret',
            description='The client secret for OAuth2 authentication.',
            ui={'hidden': False},
            value='',
            optional= False,
            secret=True
        ),
        Parameter(
            name=CustomParams.DrspayloadReceiverEndpointUrl,
            type='string',
            title='Endpoint URL',
            description='The URL of the API endpoint to make requests to.',
            ui={'hidden': False},
            value='',
            optional=False,
            secret=False
        ),
        Parameter(
            name=CustomParams.ShouldExecuteSendPayload,
            type='boolean',
            title='Perform Send Payload?',
            ui={'hidden': False},
            description='Check this box if you want to utilise Send Payload in this flow',
            value=False,
            optional=False,
        ),
        Parameter(
            name=CustomParams.DrsScopeSendPayload,
            type='string',
            title='Scope',
            ui={'hidden': False},
            description='The Scope of API to give access',
            value='',
            optional=False,
            secret=False
        )
    ]
    manifest.input.extend(wf_params)

    manifest.ui['groups'].append(
        {
            'title': 'SE Demo - Redaction Standard Settings',
            'fields': [
                'regex_map',
                'keyword_map',
                CustomParams.SendRequiredFieldsToSupervisionIfBlank,
                CustomParams.ShouldExecuteFPT,
                CustomParams.ShouldExecuteER,
                CustomParams.ShouldRedactER,
                CustomParams.ShouldRedactLayoutFields,
                CustomParams.RedactLayoutFields,
                CustomParams.ShouldRedactLayoutFieldsOutputName,
                CustomParams.DrspayloadReceiverEndpointUrl,
                CustomParams.DrspayloadReceiverClientId,
                CustomParams.DrspayloadReceiverClientSecret,
                CustomParams.DrspayloadReceiverOauth2AuthorizationUrl,
                CustomParams.DrsScopeSendPayload,
                CustomParams.ShouldExecuteSendPayload
            ]
        }
    )


    bootstrap_submission = idp_blocks.SubmissionBootstrapBlock(
        reference_name='submission_bootstrap'
    )

    case_collation_task = idp_blocks.MachineCollationBlock(
        reference_name='machine_collation',
        submission=bootstrap_submission.output('submission'),
        cases=bootstrap_submission.output('api_params.cases'),
    )

    machine_classification = idp_blocks.MachineClassificationBlock(
        reference_name='machine_classification',
        submission=case_collation_task.output('submission'),
        api_params=bootstrap_submission.output('api_params'),
    )

    manual_classification = idp_blocks.ManualClassificationBlock(
        reference_name='manual_classification',
        submission=machine_classification.output('submission'),
        api_params=bootstrap_submission.output('api_params'),
    )

    machine_identification = idp_blocks.MachineIdentificationBlock(
        reference_name='machine_identification',
        submission=manual_classification.output('submission'),
        api_params=bootstrap_submission.output('api_params'),
    )

    manual_identification = idp_blocks.ManualIdentificationBlock(
        reference_name='manual_identification',
        submission=machine_identification.output('submission'),
        api_params=bootstrap_submission.output('api_params'),
    )

    machine_transcription = idp_blocks.MachineTranscriptionBlock(
        reference_name='machine_transcription',
        submission=manual_identification.output('submission'),
        api_params=bootstrap_submission.output('api_params'),
    )
        # This piece of code checks if required fields are blank and marks them for manual transcription
    def _find_required_blanks(submission: Any, send_fields: bool, ) -> Any:
        if send_fields:
            for document in submission.get('documents', []):
                for field in document.get('document_fields', []):
                    if field.get('required', False) and not field.get('transcription', ''):
                        field['transcription_confidence'] = 'not_sure'
        return submission

    # This code block utlises the _find_required_blanks function above
    find_required_blanks = CodeBlock(
        reference_name='find_required_blanks',
        title='Check Required Fields',
        description='Checks Required Fields for Blank Transcription',
        code=_find_required_blanks,
        code_input={
            'submission': machine_transcription.output('submission'),
            'send_fields': workflow_input(CustomParams.SendRequiredFieldsToSupervisionIfBlank),
        },
    )

    manual_transcription = idp_blocks.ManualTranscriptionBlock(
        reference_name='manual_transcription',
        submission=machine_transcription.output('submission'),
        api_params=bootstrap_submission.output('api_params'),
    )

    # This block loads the submission from the API so we can see the full submission JSON in the Transformed JSON output
    def _load_submission(submission: Any, ) -> Any:
        import inspect

        submission_id_ref = submission['id']
        proxy = inspect.stack()[1].frame.f_locals['proxy']
        r = proxy.sdm_get(f'api/v5/submissions/{submission_id_ref}?flat=False')
        return r.json()

    # Executes the _load_submission code block above
    load_submission = CodeBlock(
        reference_name='load_submission',
        code=_load_submission,
        code_input={
            'submission': manual_transcription.output('submission'),
        },
        title='Load Submission',
        description='Returns Submission in API v5 Format to add post processing items to',
    )

    ''' This is the code that checks whether they are any unassigned pages. 
        It first checks whether the user wants to perform FPT from the Flow setting
        If the user does want to use FPT then check if unassigned pages are in the submission
        and send them to FPT
    '''

    def _should_execute_fpt(submission: Any, decision: Any) -> Any:
        return {'submission': submission, 'decision': decision}

    # This is the code block which executes the _should_execute_fpt function above
    should_execute_fpt = CodeBlock(
        reference_name='should_execute_fpt',
        code=_should_execute_fpt,
        code_input={
            'submission': load_submission.output(),
            'decision': workflow_input(CustomParams.ShouldExecuteFPT),
        },
        title='Should Execute Full Page Transcription, or Redact Named Layout Fields?',
        description=(
            "If Yes, send unassigned pages to FPT and if required, redact named fields in layouts"
        ),
    )

    # This is the code that is executed if should_execute_fpt returns a decision of 'No'
    def _no_op_fpt(submission: Dict) -> Dict:
        return {'submission': submission, 'negative_sentiment': 'false'}

    # This is the code block which executes the _no_op_fpt function above
    no_op_fpt = CodeBlock(
        reference_name='no_op_fpt',
        title='No FPT',
        description='Pass the existing submission along without any changes',
        code=_no_op_fpt,
        code_input={'submission': load_submission.output()},
    )

    # This block performs FPT on unassigned pages if should_execute_fpt returns a decision of 'Yes'
    fpt_unassigned_pages = IDPFullPageTranscriptionBlock(
        submission=manual_classification.output('submission'),
        reference_name='fpt_unassigned_pages',
        title='FPT Unassigned Pages',
        description='Perform FPT on any unassigned pages',
    )

    # This code merges the output of FPT block back into the main submission
    def _merge_pages_into_submission_fn(submission: Any, pages: Any) -> Any:
        id_to_page = dict()
        for page in pages:
            id_to_page[page['id']] = page

        for page in submission['unassigned_pages']:
            page['image_uuid'] = id_to_page[page['id']]['image_uuid']
            page['segments'] = id_to_page[page['id']]['segments']

        return submission

    '''This is the code block which executes the _merge_pages_into_submission_fn function above
       This takes the submission object from the load_submission code block and the page object 
       from the fpt_unassigned_pages block as its input
    '''
    merge_pages_into_submission = CodeBlock(
        reference_name='merge_pages_into_submission',
        title='Merge Pages into Submission',
        description='Merge pages into submission',
        code=_merge_pages_into_submission_fn,
        code_input={
            'submission': load_submission.output(),
            'pages': fpt_unassigned_pages.output('submission.unassigned_pages'),
        },
    )

    # This code block determines whether ER should be performed based on Flow settings
    def _should_execute_er(submission: Any, decision: Any) -> Any:
        return {'submission': submission, 'decision': decision}
    
    # This is the code block which executes the _should_execute_er function above
    should_execute_er = CodeBlock(
        reference_name='should_execute_er',
        code=_should_execute_er,
        code_input={
            'submission': merge_pages_into_submission.output(),
            'decision': workflow_input(CustomParams.ShouldExecuteER),
        },
        title='Should Execute Entity Recognition?',
        description=(
            "Do you want to perform ER on unassigned pages in the Submission? Defined by checkbox in Flow Settings"
        ),
    )
    
    # This block performs Entity Recognition on Unassigned pages
    er = EntityRecognitionBlock(
        reference_name='er',
        pages=fpt_unassigned_pages.output('submission.unassigned_pages'),
        regex_map=DEFAULT_PII_REGEX_MAP,
        keyword_map=DEFAULT_PII_KEYWORD_MAP,
    )
    
    # This function generates color-coded visualizations on the unassigned pages by adding bounding
    # boxes to each entity recognized. Option to redact instead which is configured from the flow settings
    def _generate_er_visualizations(submission: Any,
                                    unassigned_pages: Any,
                                    er_output: Any,
                                    redact: Any,
                                    _hs_block_instance: HsBlockInstance) -> Any:
        import cv2
        import tempfile
        import os
        import subprocess
        from collections import defaultdict

        # pylint: disable=import-error
        from sdm_image.image_utils.image_read import blob_to_cv2_image  # type: ignore
    
        if not er_output['documents']:
            return submission
    
        # Define colors for different entity types
        color = {
            'Person Name': (255, 0, 0),
            'Organization Name': (0, 255, 0),
            'Location': (0, 0, 255),
            'policy number': (255, 20, 147),
            'loan number': (255, 20, 147),
            'credit card number': (255, 20, 147),
            'customer id': (255, 20, 147),
            'account number': (255, 20, 147),
            'employee id': (255, 20, 147),
            'employer id': (255, 20, 147),
            'ssn': (255, 20, 147),
            'email': (255, 20, 147),
            'us phone number': (255, 20, 147),
            'date': (255, 20, 147),
            'passport number': (255, 20, 147),
            'uscis number': (255, 20, 147),
            'driver license number': (255, 20, 147),
            'i94 number': (255, 20, 147),
            'pin number': (255, 20, 147),
            'micr': (255, 20, 147),
            'ptin number': (255, 20, 147),
            'judgment number': (255, 20, 147),
            'case number': (255, 20, 147),
            'bankruptcy number': (255, 20, 147),
            'application number': (255, 20, 147),
            'file number': (255, 20, 147),
            'routing number': (255, 20, 147),
            'nmls number': (255, 20, 147),
            'appraiser certification number': (255, 20, 147),
            'driver license restrictions': (255, 20, 147),
            'machine readable line': (255, 20, 147),
            'address' : (255, 20, 147),
        }

        thickness = 2
    
        er_document = er_output['documents'][0]
        custom_fields_er = defaultdict(list)
        images = []
    
        for page in unassigned_pages:
            image_blob = _hs_block_instance.fetch_blob(page['image_uuid']).content
            image = blob_to_cv2_image(image_blob)
            image = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
            images.append(image)
    
        for prediction in er_document['predictions']:
            custom_fields_er[prediction['type']].append(prediction['text'])
            for position, page_id in zip(prediction['positions'], prediction['page_ids']):
                h, w, _ = images[page_id].shape

                start_x, start_y, end_x, end_y = position
                start_point = (
                    int(w * start_x),
                    int(h * start_y),
                )
                end_point = (
                    int(w * end_x),
                    int(h * end_y),
                )

                if redact:
                    images[page_id] = cv2.rectangle(
                        images[page_id], start_point, end_point, (0, 0, 0), -1
                    )
                else:
                    images[page_id] = cv2.rectangle(
                        images[page_id], start_point, end_point, color[prediction['type']], thickness
                    )

        try:
            annotated_images = []
            for image in images:
                tmp_file = tempfile.NamedTemporaryFile()
                tmp_file.write(cv2.imencode('.tiff', image)[1].tobytes())
                tmp_file.flush()
                os.fsync(tmp_file.fileno())
                annotated_images.append(tmp_file)

            if annotated_images:
                annotated_images.append(tempfile.NamedTemporaryFile())
                command = ['tiffcp', *[image_file.name for image_file in annotated_images]]

                subprocess.run(
                    command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )

                annotated_images.append(tempfile.NamedTemporaryFile())
                command = ['tiff2pdf', '-o', annotated_images[-1].name, '-F', annotated_images[-2].name]

                subprocess.run(
                    command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )

                with open(annotated_images[-1].name, 'rb') as f:
                    blob_file = _hs_block_instance.store_blob(
                        StoreBlobRequest(name='document_{}_redacted_er.pdf'.format(submission['id']), content=f.read())
                    )   
                er_document['result'] = '/api/block_storage/{}/download'.format(
                    blob_file.uuid)

        finally:
            for image_file in annotated_images:
                image_file.close()
    
        submission['unassigned_pages'][0]['er_predictions_pdf'] = er_document.get('result')
        submission['unassigned_pages'][0]['custom_fields_er'] = custom_fields_er
    
        return submission
    
    # This block executes the _generate_er_visualizations code block above
    er_visualization_block = CodeBlock(
        reference_name='generate_er_visualizations',
        code=_generate_er_visualizations,
        code_input={
            'submission': merge_pages_into_submission.output(),
            'unassigned_pages': merge_pages_into_submission.output('unassigned_pages'),
            'er_output': er.output(),
            'redact': workflow_input(CustomParams.ShouldRedactER)
        },
        title='Generate Visualizations',
        description='Highlights the ER entities on the document',
    )
    
    # This is the code that is executed if should_execute_er returns a decision of 'No'
    def _no_op_er(submission: Dict) -> Dict:
        return submission
    
    # This is the code block which executes the _no_op_er function above
    no_op_er = CodeBlock(
        reference_name='no_op_er',
        title='No ER',
        description='Pass the existing submission along without any changes',
        code=_no_op_er,
        code_input={'submission': merge_pages_into_submission.output()},
    )
    
    # This is the routing block which contains the ER-related blocks above and creates the branches
    # The Yes or No decision is determined by the output of the should_execute_er block
    # If Yes then er and er_visualization_block blocks are executed
    # If No then no_op_er block is executed
    er_routing = Routing(
        reference_name='er_routing',
        decision=should_execute_er.output('decision'),
        branches=[
            Routing.Branch(
                case='true',
                blocks=[
                    er,
                    er_visualization_block
                ],
                label='Perform ER',
                output=er_visualization_block._reference_name,
            ),
            Routing.Branch(
                case='false',
                blocks=[no_op_er],
                label='No ER',
                output=no_op_er._reference_name,
            )
        ]
    )

    def _execute_redaction(
            submission: Any,
            layout_field_decision: Any,
            layout_fields: Any,
            redact_field_outputname_decision: Any,
            load_submission: Any,
            _hs_block_instance: HsBlockInstance
    ) -> Any:

        import inspect
        import cv2
        import tempfile
        import os
        import subprocess
        from collections import defaultdict

        # pylint: disable=import-error
        from sdm_image.image_utils.image_read import blob_to_cv2_image  # type: ignore

        if not layout_field_decision and not redact_field_outputname_decision:
            return submission

        # redact named fields in layouts
        if layout_field_decision and layout_fields:

            if submission['documents']:

                pages_processed = []
                page_images = {}
                field_image_details = {}
                field_list = [x.strip() for x in layout_fields.split(',')]
                fields_found = []
                images = []

                # Loop through each document in the submission.
                for document in submission['documents']:

                    '''Loop through each page in the document and find the corrected image,
                    extract the image uuid and add it to a dict using the page_id as the key
                    '''
                    # for page in document['pages']:
                    #     page_id = page['id']
                    #     corrected_image_url = page['corrected_image_url']
                    #     corrected_uuid = corrected_image_url[14:]
                    #     image_blob = _hs_block_instance.fetch_blob(corrected_uuid).content
                    #     image = blob_to_cv2_image(image_blob)
                    #     image = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
                    #     page_images[page_id] = image

                    '''Loop through each field in the document to see if it is in the list of fields
                       that need to be redacted. If it is get the image URL and extract the x and y
                       coordinates. 
                    '''
                    for field in document['document_fields']:
                        if field['name'] in field_list:
                            fields_found.append(field['name'])
                            field_id = field['id']
                            field_page_id = field['page_id']
                            for page in document['pages']:
                                page_id = page['id']
                                if page_id == field_page_id:
                                    corrected_image_url = page['corrected_image_url']
                                    corrected_uuid = corrected_image_url[14:]
                                    image_blob = _hs_block_instance.fetch_blob(corrected_uuid).content
                                    image = blob_to_cv2_image(image_blob)
                                    image = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
                                    page_images[page_id] = image

                            field_image_url = field['field_image_url']
                            url_components = field_image_url.split('?')
                            location = url_components[1]
                            location_components = location.split('&')

                            start_x_components = location_components[0].split('=')
                            start_x = start_x_components[1]

                            start_y_components = location_components[1].split('=')
                            start_y = start_y_components[1]

                            end_x_components = location_components[2].split('=')
                            end_x = end_x_components[1]

                            end_y_components = location_components[3].split('=')
                            end_y = end_y_components[1]

                            field_details = [field_page_id, start_x, start_y, end_x, end_y]
                            field_image_details[field_id] = field_details

                    # draw redaction boxes
                    for page_id in page_images.keys():
                        if page_id not in pages_processed:
                            image = page_images[page_id]
                            h, w, _ = image.shape

                            for field_id in field_image_details.keys():
                                field_details = field_image_details[field_id]
                                field_page_id = field_details[0]
                                if field_page_id == page_id:
                                    start_x = float(field_details[1])
                                    start_y = float(field_details[2])
                                    end_x = float(field_details[3])
                                    end_y = float(field_details[4])

                                    start_point = (
                                        int(w * start_x),
                                        int(h * start_y),
                                    )
                                    end_point = (
                                        int(w * end_x),
                                        int(h * end_y),
                                    )

                                    page_images[page_id] = cv2.rectangle(
                                        page_images[page_id], start_point, end_point, (0, 0, 0), -1
                                    )
                            images.append(page_images[page_id])
                            pages_processed.append(page_id)

                if fields_found:
                    # create redacted pdf
                    try:
                        annotated_images = []
                        # for image in page_images.keys():
                        for image in images:
                            tmp_file = tempfile.NamedTemporaryFile()
                            tmp_file.write(cv2.imencode('.tiff', image)[1].tobytes())
                            tmp_file.flush()
                            os.fsync(tmp_file.fileno())
                            annotated_images.append(tmp_file)

                        if annotated_images:
                            annotated_images.append(tempfile.NamedTemporaryFile())
                            command = ['tiffcp', *[image_file.name for image_file in annotated_images]]

                            subprocess.run(
                                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                            )

                            annotated_images.append(tempfile.NamedTemporaryFile())
                            command = ['tiff2pdf', '-o', annotated_images[-1].name, '-F', annotated_images[-2].name]

                            subprocess.run(
                                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                            )

                            with open(annotated_images[-1].name, 'rb') as f:
                                blob_file = _hs_block_instance.store_blob(
                                    StoreBlobRequest(
                                        name='document_{}_redacted_layout_fields.pdf'.format(submission['id']),
                                        content=f.read())
                                )

                    finally:
                        for image_file in annotated_images:
                            image_file.close()

                if 'redacted_fields_looked_for' not in submission:
                    submission['redacted_fields_looked_for'] = []
                    submission['redacted_fields_looked_for'] = field_list

                if 'redacted_fields_found' not in submission:
                    submission['redacted_fields_found'] = []
                    submission['redacted_fields_found'] = fields_found

                if fields_found:
                    if 'redacted_layout_fields_pdf' not in submission:
                        submission['redacted_layout_fields_pdf'] = []
                        submission['redacted_layout_fields_pdf'] = '/api/block_storage/{}/download'.format(
                            blob_file.uuid)

        # Redact fields that are marked with 'REDACT_' in their layout's out-put-names
        if redact_field_outputname_decision:

            if submission['documents']:

                pages_processed_redact_ = []
                page_images_redact_ = {}
                field_image_details_redact_ = {}
                fields_found_redact_ = []
                images_redact_ = []

                # Loop through each document in the submission.
                for document in submission['documents']:

                    for field in document['document_fields']:
                        if field['output_name'] == 'REDACT_':
                            fields_found_redact_.append(field['name'])
                            field_id = field['id']
                            field_page_id = field['page_id']
                            for page in document['pages']:
                                page_id = page['id']
                                if page_id == field_page_id:
                                    corrected_image_url = page['corrected_image_url']
                                    corrected_uuid = corrected_image_url[14:]
                                    image_blob = _hs_block_instance.fetch_blob(corrected_uuid).content
                                    image = blob_to_cv2_image(image_blob)
                                    image = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
                                    page_images_redact_[page_id] = image

                            field_image_url = field['field_image_url']
                            url_components = field_image_url.split('?')
                            location = url_components[1]
                            location_components = location.split('&')

                            start_x_components = location_components[0].split('=')
                            start_x = start_x_components[1]

                            start_y_components = location_components[1].split('=')
                            start_y = start_y_components[1]

                            end_x_components = location_components[2].split('=')
                            end_x = end_x_components[1]

                            end_y_components = location_components[3].split('=')
                            end_y = end_y_components[1]

                            field_details = [field_page_id, start_x, start_y, end_x, end_y]
                            field_image_details_redact_[field_id] = field_details

                    # draw redaction boxes
                    for page_id in page_images_redact_.keys():
                        if page_id not in pages_processed_redact_:
                            image = page_images_redact_[page_id]
                            h, w, _ = image.shape

                            for field_id in field_image_details_redact_.keys():
                                field_details = field_image_details_redact_[field_id]
                                field_page_id = field_details[0]
                                if field_page_id == page_id:
                                    start_x = float(field_details[1])
                                    start_y = float(field_details[2])
                                    end_x = float(field_details[3])
                                    end_y = float(field_details[4])

                                    start_point = (
                                        int(w * start_x),
                                        int(h * start_y),
                                    )
                                    end_point = (
                                        int(w * end_x),
                                        int(h * end_y),
                                    )

                                    page_images_redact_[page_id] = cv2.rectangle(
                                        page_images_redact_[page_id], start_point, end_point, (0, 0, 0), -1
                                    )
                            images_redact_.append(page_images_redact_[page_id])
                            pages_processed_redact_.append(page_id)

                if fields_found_redact_:
                    # create redacted pdf
                    try:
                        annotated_images_redact_ = []
                        # for image in page_images_redact_.keys():
                        for image in images_redact_:
                            tmp_file = tempfile.NamedTemporaryFile()
                            tmp_file.write(cv2.imencode('.tiff', image)[1].tobytes())
                            tmp_file.flush()
                            os.fsync(tmp_file.fileno())
                            annotated_images_redact_.append(tmp_file)

                        if annotated_images_redact_:
                            annotated_images_redact_.append(tempfile.NamedTemporaryFile())
                            command = ['tiffcp', *[image_file.name for image_file in annotated_images_redact_]]

                            subprocess.run(
                                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                            )

                            annotated_images_redact_.append(tempfile.NamedTemporaryFile())
                            command = ['tiff2pdf', '-o', annotated_images_redact_[-1].name, '-F',
                                       annotated_images_redact_[-2].name]

                            subprocess.run(
                                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                            )

                            with open(annotated_images_redact_[-1].name, 'rb') as f:
                                blob_file = _hs_block_instance.store_blob(
                                    StoreBlobRequest(
                                        name='document_{}_redacted_layout_fields.pdf'.format(submission['id']),
                                        content=f.read())
                                )

                    finally:
                        for image_file in annotated_images_redact_:
                            image_file.close()

                if 'redacted_fields_found_redact_' not in submission:
                    submission['redacted_fields_found_redact_'] = []
                    submission['redacted_fields_found_redact_'] = fields_found_redact_

                if fields_found_redact_:
                    if 'redacted_layout_fields_pdf_redact_' not in submission:
                        submission['redacted_layout_fields_pdf_redact_'] = []
                        submission['redacted_layout_fields_pdf_redact_'] = '/api/block_storage/{}/download'.format(
                            blob_file.uuid)

        return submission

    # This blocks executes the _execute_redaction function above
    execute_redaction = CodeBlock(
        reference_name='execute_redaction',
        code=_execute_redaction,
        code_input={
            'submission': load_submission.output(),
            'layout_field_decision': workflow_input(CustomParams.ShouldRedactLayoutFields),
            'layout_fields': workflow_input(CustomParams.RedactLayoutFields),
            'redact_field_outputname_decision': workflow_input(CustomParams.ShouldRedactLayoutFieldsOutputName),
            'load_submission': load_submission.output(),
        },
        title='Redact Layout Fields',
        description='Redact layout fields for structured/semi-structured layouts'
    )  

    fpt_routing = Routing(
        reference_name='fpt_routing',
        decision=should_execute_fpt.output('decision'),
        branches=[
            Routing.Branch(
                case='true',
                blocks=[
                    fpt_unassigned_pages,
                    merge_pages_into_submission,
                    should_execute_er,
                    er_routing,
                    execute_redaction,
                ],
                label='FPT',
                output=execute_redaction._reference_name,

            ),
            Routing.Branch(
                case='false',
                blocks=[no_op_fpt],
                label='No FPT',
                output=no_op_fpt._reference_name,
            )
        ]
    )
        # Function to load the full submission data
    def _load_full_submission(submission):
        import inspect

        submission_id_ref = submission['id']
        proxy = inspect.stack()[1].frame.f_locals['proxy']
        response = proxy.sdm_get(f'api/v5/submissions/{submission_id_ref}?flat=False')
        return response.json()

    def prepare_transformed_output(submission, complete_data):
        from datetime import datetime
        dt_completed_fmt = datetime.isoformat(datetime.utcnow()) + 'Z'

        # Initialize the transformed output with required fields
        transformed_output = {
            "id": submission.get("id"),
            "external_id": submission.get("external_id"),
            "state": submission.get("state", "complete"),
            "exceptions": submission.get("exceptions", []),
            "start_time": submission.get("start_time"),
            "submission_files": submission.get("submission_files", []),
            "complete_time": dt_completed_fmt,  # Mark the transformation completion time
            "documents": [],
            "filtered_unassigned_pages": [],
            "redacted_fields_looked_for": complete_data.get('redacted_fields_looked_for', []),
            "redacted_fields_found": complete_data.get('redacted_fields_found', []),
            "redacted_layout_fields_pdf": complete_data.get('redacted_layout_fields_pdf', None)
        }


        # Process documents if present
        if "documents" in submission:
            for document in submission["documents"]:
                transformed_document = {
                    "id": document.get("id"),
                    "submission_id": document.get("submission_id"),
                    "state": document.get("state", "complete"),  # Defaulting to "complete" if not specified
                    "exceptions": document.get("exceptions", []),
                    "layout_name": document.get("layout_name"),
                    "layout_variation_name": document.get("layout_variation_name"),
                    "type": document.get("type"),
                    "document_type": document.get("layout_name"),  # Assuming layout_name as document_type
                    "document_fields": [],
                }

                # Process document fields if present
                if "document_fields" in document:
                    for field in document["document_fields"]:
                        transformed_field = {
                            "id": field.get("id"),
                            "state": field.get("state", "complete"),
                            "exceptions": field.get("exceptions", []),
                            "name": field.get("name"),
                            "page_id": field.get("page_id"),
                            "transcription": field.get("transcription", {}).get("normalized"),
                        }
                        # Append transformed field to the document's fields list
                        transformed_document["document_fields"].append(transformed_field)

                # Append transformed document to the output's documents list
                transformed_output["documents"].append(transformed_document)

        # Handle unassigned pages if present
        if "unassigned_pages" in submission:
            transformed_output["filtered_unassigned_pages"] = [
                {key: page.get(key) for key in [
                    "submission_page_number", "file_page_number", "layout_page_number", 
                    "layout_variation_page_number", "document_page_number", "submitted_filename", "image_url"
                ]} for page in submission["unassigned_pages"]
            ]

        return transformed_output

    # Complete the submission
    submission_complete = idp_blocks.SubmissionCompleteBlock(
        reference_name='complete_submission',
        submission=execute_redaction.output(),
        payload=execute_redaction.output(),
    )
        # Executes the _load_submission code block above
    load_full_submission = CodeBlock(
        reference_name='load_full_submission',
        code=_load_full_submission,
        code_input={
            'submission': submission_complete.output('submission'),
        },
        title='Load Submission',
        description='Returns Submission in API v5 Format to add post processing items to',
    )

    transformed_output_block = CodeBlock(
        reference_name='prepare_transformed_output',
        code=prepare_transformed_output,
        code_input={
             'submission': load_full_submission.output(),
             'complete_data': execute_redaction.output(),
        },
        title='Prepare Transformed Output',
        description='Transforms submission data by filtering specific fields and marking the state as complete.',
    )
    
    ''' This is the code that checks whether you want to perform an Send Payload
        based upon the Flow Setting in Custom Parameters
    '''

    def _should_execute_send_payload(submission: Any, decision: Any) -> Any:
        return {'submission': submission, 'decision': decision}

    # This is the code block which executes the _should_execute_send_payload function above
    should_execute_send_payload = CodeBlock(
        reference_name='should_execute_send_payload',
        code=_should_execute_send_payload,
        code_input={
            'submission': load_full_submission.output(),
            'decision': workflow_input(CustomParams.ShouldExecuteSendPayload),
        },
        title='Should Execute Send Payload?',
        description=(
            "If the Flow Setting has been checked, then this block will perform Send Payload."
        ),
    )


    
    def _send_payload(submission: Any, DrspayloadReceiverOauth2AuthorizationUrl: Any, DrspayloadReceiverClientId: Any, DrspayloadReceiverClientSecret: Any, DrspayloadReceiverEndpointUrl: Any,DrsScopeSendPayload: Any):
        import requests
        import json
        try:
            # Get the OAuth2 token
            token_response = requests.post(
                DrspayloadReceiverOauth2AuthorizationUrl,
                data={'grant_type': 'client_credentials','scope': DrsScopeSendPayload, 'client_id': DrspayloadReceiverClientId, 'client_secret': DrspayloadReceiverClientSecret},
                # auth=(DrspayloadReceiverClientId, DrspayloadReceiverClientSecret)
            )
            token_response.raise_for_status()  # Ensure the request was successful
            access_token = token_response.json().get('access_token')
            
            # Check if access token is successfully retrieved
            if not access_token:
                raise ValueError("Failed to retrieve access token")

            # Prepare the submission data
            submission_data = submission
            print(submission_data)

            # Send the data to the DrspayloadReceiverEndpointUrl
            response = requests.post(
                DrspayloadReceiverEndpointUrl,
                json=submission_data,
                headers={'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
            )

            # Check the response content type
            content_type = response.headers.get('Content-Type', '').lower()
            
            if 'application/json' in content_type:
                return response.json()
            elif 'text/xml' in content_type:
                # Handle XML response
                return {'xml_response': response.text}
            else:
                # Handle other types of responses
                return {'error': f'Unsupported content type: {content_type}'}

        except Exception as e:
            # Log the error for debugging
            print("Error in _send_payload")
            return {'error': 'Failed to send payload', 'exception': str(e)}



    send_payload = CodeBlock(
        reference_name='send_payload',
        code=_send_payload, 
        code_input={
            'submission': transformed_output_block.output(),
            'DrspayloadReceiverOauth2AuthorizationUrl': workflow_input(CustomParams.DrspayloadReceiverOauth2AuthorizationUrl),
            'DrspayloadReceiverClientId': workflow_input(CustomParams.DrspayloadReceiverClientId),
            'DrspayloadReceiverClientSecret': workflow_input(CustomParams.DrspayloadReceiverClientSecret),
            'DrspayloadReceiverEndpointUrl': workflow_input(CustomParams.DrspayloadReceiverEndpointUrl),
            'DrsScopeSendPayload': workflow_input(CustomParams.DrsScopeSendPayload),
        },
    )


    def no_op_sendpayload(submission: Dict) -> Dict:
        return submission  # Just returns what it receives without any modification
    
    no_op_send_payload = CodeBlock(
        reference_name='no_op_send_payload',
        code=no_op_sendpayload,
        code_input={'submission': transformed_output_block.output()},
        title='No Payload',
        description='Passes the existing submission without any payload.'
    )


    # Then your Routing block should look like this
    sendpayload_routing = Routing(
        reference_name='sendpayload_routing',
        decision=should_execute_send_payload.output('decision'),
        branches=[
            Routing.Branch(
                case='true',
                blocks=[send_payload],
                label='Perform Send payload',
                output=send_payload._reference_name,
            ),
            Routing.Branch(
                case='false',
                blocks=[no_op_send_payload],
                label='No Payload',
                output=no_op_send_payload._reference_name,
            )
        ]
    )

    outputs = IDPOutputsBlock(inputs={'submission': transformed_output_block.output()})



    ''' Build the flow
        Create a unique UUID if using this code to create your own flow - https://www.uuidgenerator.net/version4
        Change owner_email if needed
        Change title if needed
        The list in the blocks[] section are the order they will be rendered in the UI
        If you have created new or renamed any blocks above ensure they are added/amended below 
    '''
    return Flow(
        uuid=UUID(IDP_UUID),
        owner_email='jeff.cahill@hyperscience.com',
        title='R39 - Redaction Master Flow 1.0',
        description='''Master Flow - Options available:

          * Option to redact layout fields in Structured and Semi-Structured documents
          * Option to redact layout fields in Structured and Semi-Structured documents that are flagged as REDACT_
            in their output name
            ''',
        manifest=manifest,
        input={},
        output={'submission': transformed_output_block.output()},
        blocks=[
            bootstrap_submission,
            case_collation_task,
            machine_classification,
            manual_classification,
            machine_identification,
            manual_identification,
            machine_transcription,
            find_required_blanks,
            manual_transcription,
            load_submission,
            should_execute_fpt,
            fpt_routing,
            submission_complete,
            load_full_submission,
            transformed_output_block,  
            should_execute_send_payload,
            sendpayload_routing,
            outputs,
        ],
    )

def entry_point_workflow() -> Flow:
    return idp_workflow()


if __name__ == '__main__':
    export_flow(entry_point_workflow())
