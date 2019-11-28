## SWIMs Overview
The files in this folder are utilised as part of the FMC build pipeline's interaction with SWIMs.

* [code_sign](code_sign) is the SWIMs tool used in both ticket creation and TLP creation. (_Note that this a 64bit binary._)
* [swims-ticket.jenkinsfile](swims-ticket.jenkinsfile) is the pipeline file used to create a SWIMs ticket

## Pipeline Stages
### SWIMs Ticket Pipeline
The SWIMs Ticket pipeline is responsible for creating and storing the SWIMs ticket which gets used by the main FMC build pipeline. There are four stages.

#### 1. Create ticket
The create ticket stage takes a one-time password and uses this to interact with SWIMs and generate a ticket request. This request contains the list of approvers. In order to add more approvers [swims-ticket.jenkinsfile](swims-ticket.jenkinsfile) needs to be updated.

#### 2. Approve ticket
The approve ticket stage takes two one-time passwords and uses these to approve the ticket request and downloand approved ticket.

#### 3. Validate ticket
The validate ticket stage takes the newly created ticket and verifies that this is a valid ticket.

#### 4. Update stored ticket
The update stored ticket stage takes the newly created ticket and updates a stored credential on Jenkins with this new ticket. This credential is a Secret Text object.

### Main Build Pipeline
In order to create a TLP a SWIMs ticket is required. In the main pipeline, the credentials object created by the SWIMs pipeline is used to create this ticket.

#### 1. Create a SWIMs Ticket
With the SWIMs credential, create a new file with the secret data.

#### 2. Pass the SWIMs Ticket to TLP creation
Pass the newly created SWIMs ticket file to the build script to create a TLP.

## Process
### Creating a new SWIMs Ticket Request
1. Open the FMC [SWIMs Ticket pipeline](https://sqbu-jenkins.wbx2.com/service07/job/team/job/management-connector/job/swims/job/swims-ticket/).
2. Click the ```Build with Parameters``` menu item.
3. Enter a one-time password (```creatorOTP```) from MobilePass, SofToken or PingID depending on which one you use.
4. Press Build.

_Once the job is started, it will reach out to SWIMs and request a ticket using the username and one-time password of the submitter. The ticket request number is stored and will be used in the next stage of the process._

### Approving a SWIMs Ticket Request
1. Open the FMC [SWIMs Ticket pipeline](https://sqbu-jenkins.wbx2.com/service07/job/team/job/management-connector/job/swims/job/swims-ticket/).
2. Click on the build that was created above and is pending approval. It's description should say "Ticket waiting for approval. Click here to approve ticket.
3. Open the console for the build.
4. Click on the "Input Requested" link at the bottom of the console.
5. Enter two one-time passwords (```otp1``` and ```otp2```) from MobilePass, SofToken or PingID depending on which one you use.
6. Click Proceed.

_Once the stage is started, it will reach out to SWIMs and approve the ticket request using the username and one-time password of the submitter. Once the ticket is approved the second one-time password is used to download the SWIMs ticket. This ticket is then validated in the next stage. In the final stage the ticket is uploaded to a secret text type credentials object called ```fmc-swims``` on Jenkins._

## Backup Process in the Event of Needing to Update the SWIMs Ticket Manually
### Creating a new SWIMs Ticket Request
1. Log in to the [SWIMs portal](https://swims.cisco.com/swims/).
2. Navigate to the [Create ticket](https://swims.cisco.com/swims/ticket/create) page.
3. Create a ticket and add the appropriate approver.
4. Click submit.

_At this point the approver will receive an email._

### Approving a SWIMs Ticket Request
1. Log in to the [SWIMs portal](https://swims.cisco.com/swims/).
2. Navigate to the [Tickets pending my approval](https://swims.cisco.com/swims/ticket/list/pending) page.
3. Select the appropriate ticket and approve it.

### Updating a SWIMs Ticket on Jenkins
1. Log in to the [SWIMs portal](https://swims.cisco.com/swims/).
2. Navigate to the [List my active tickets](https://swims.cisco.com/swims/ticket/list/active) page.
3. Select the appropriate ticket and download it.
4. Log in to Jenkins and navigate to the [fmc-swims credential](https://sqbu-jenkins.wbx2.com/service07/job/team/job/management-connector/job/pipeline/credentials/store/folder/domain/_/credential/fmc-swims/).
5. CLick Update.
6. Paste the text from the SWIMs ticket into the ```Secret``` field and click Save.
