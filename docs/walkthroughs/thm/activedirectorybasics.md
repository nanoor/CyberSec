---
title: Active Directory Basics
desc: >-
  THM: This room will introduce the basic concepts and functionality provided by
  Active Directory.
---
## Introduction
!!! note
    Microsoft's Active Directory is the backbone of the corporate world. It simplifies the management of devices and users within a corporate environment. In this room, we'll take a deep dive into the essential components of Active Directory.

This room will cover basic concepts related to Active Directory including the following topics:

- What is Active Directory?
- What is an Active Directory Domain?
- What components go into an Active Directory Domain?
- Forests and Domain Trust

## Windows Domains
Windows domain is a group of users and computer under the administration of a given business. Windows domains provide network administrators with a way to manage a large number of endpoints and control them from one place. Windows domains are generally made up of computers on the same local network; however computers joined to a domain can continue communicating with their domain controller over VPN or Internet connection thus allowing remote access.

In other words, the main idea behind a domain is to centralize the administration of common components of a Windows computer network in a single repository called *Active Directory (AD)*. The server that runs the Active Directory services is known as a *Domain Controller (DC)*.

When a computer is joined to a domain, it does not use its own local user accounts. User accounts and passwords are managed on the domain controller. Logging into a computer on that domain, the computer authenticates your user account name and password with the domain controller. This means you can log in with the same username and password on any computer joined to the domain.

![Windows Domain](../../assets/images/thm/activedirectorybasics/01%20-%20domain.png)

Some key advantages of having a configured Windows domain are:

- **Centralized identity management**: All users across the network can be configured from Active Directory with minimum effort.
- **Managing security policies**: Security policies can be configured directly from Active Directory and applied to users and computers across the network as needed.

## Active Directory
The core of any Windows domain is the *Active Directory Domain Service (AD DS)*. This service holds all relevant information related to objects that exist on the network.

### Users
Users are one of the most common object types in Active Directory. Users are one of the objects known as ***security principals*** which means that they can be authenticated by the domain and can be assigned privileges over resources like files or printers. In other words, a security principal is an object that can act upon resources in the network.

Users can be represented by two types of entities:

- **People**: Users will generally represent persons in an organization that need access to the network (ie. employees).
- **Services**: You can also define users to be used by services like IIS or MSSQL. Every single service requires a user to run but service users are different from regular users as they will only have the privileges to run their specific service.

### Machines
Machines are another type of object within Active Directory. For every computer that joins the Active Directory domain, a machine object will be created. Machines are also considered security principals in much the same way as users and are assigned an account just as any regular user. These accounts have somewhat limited rights within the domain controller itself.

The machine accounts themselves are local administrators on the assigned computer and are generally not supposed to be accessed by anyone except the computer itself. It should be noted that if you have the password to the machine account, you can use it to log in.

**Note:** Machine account passwords are automatically rotated out and are generally comprised of 120 random characters.

Machine accounts follow a specific naming scheme thus making them easy to identify. The machine account name is the computer's name followed by a dollar sign. For example, a machine named `DC01` will have a machine account called `DC01$`.

### Security Groups
Security groups are a way of collecting user accounts, machine accounts, and other groups into manageable units. Working with groups instead of with individual users helps simplify network administration since any account added to an existing group will automatically inherit all of the group's privileges. Security groups are also considered security principals and as such can have privileges over resources on the network.

Groups can have both users and machines as members. If required, groups can include other groups as well. Several groups are created by default in a domain that can be used to grant specific privileges to the users. The following are some important groups in a domain:

|Security Group|Description|
|:-:|:--|
|Domain Admins|Users of this group have administrative privileges over the entire domain. By default, they can administer any computer on the domain, including Domain Controllers.|
|Server Operators|Users in this group can administer Domain Controllers. They cannot change any administrative group memberships.|
|Backup Operators|Users in this group are allowed to access any file, ignoring their permissions. They are used to perform backups of data on computers.|
|Account Operators|Users in this group can create or modify other accounts in the domain.|
|Domain Users|Includes all existing user accounts in the domain.|
|Domain Computers|Include all existing computers/machines in the domain.|
|Domain Controllers|Include all existing Domain Controllers on the domain.|

A complete list of default security groups can be obtained from the [Microsoft documentation on Active Directory security groups](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups).

## Active Directory Users and Computers
To configure users, groups, or machines in Active Directory, we need to log into the Domain Controller and run `Active Directory Users and Computers` from the start menu.

![Active Directory Users and Computers Search](../../assets/images/thm/activedirectorybasics/02%20-%20active%20directory%20users%20and%20computer%20search.png)

This will open up a window where you can see the hierarchy of users, computers, and groups that exist in the domain. These objects are organized in **Organizational Units (OUs)** which are container objects that allow you to classify users and machines. OUs are mainly used to define sets of users with similar policing requirements (ie. Sales staff vs Engineering Staff vs Marketing Staff vs IT). 

!!! note
    A user can only be part of a single OU at a time.

![Active Directory Users and Computer](../../assets/images/thm/activedirectorybasics/03%20-%20active%20directory%20users%20and%20computers.png)

In the above example, we can see that there is already an OU called `THM` with five child OUs for the IT, Management, Marketing, Research and Development, and Sales. It is very typical for OUs to mimic the business' structure as it allows for efficient deployment of baseline policies that apply to the entire department.

Opening any OU reveals the users they contain. Here we can perform simple tasks like creating, deleting, or modifying the users as needed. Password reset can also be done here if needed.

![Organizational Unit](../../assets/images/thm/activedirectorybasics/04%20-%20OU.png)

Apart from the custom `THM` OU, Windows automatically creates the following default containers (or OUs):

- **Builtin**: Contains default groups available to any Windows host.
- **Computers**: Contains any machine that joins the network by default. These machines can be moved if needed.
- **Domain Controllers**: Default OU that contains the Domain Controllers in the network.
- **Users**: Default users and groups that apply to a domain-wide context.
- **Managed Service Accounts**: Holds accounts used by services in the Windows domain.

### Security Groups vs OUs
Both security groups and OUs are used to classify users and computers but their purposes are entirely different:

- **OUs**: Used for *applying policies* to users and computers which include specific configurations that pertain to sets of users depending on their particular role in the enterprise. A user can only be a member of a single OU at a time.
- **Security Groups**: Used to *grant permissions over resources* (ie: allow some users to access a shared folder or a network printer). A user can be part of many groups which is needed to grant access to multiple resources.

## Managing Users in Active Directory
In this section, will look at managing users within the existing Active Directory OUs.

### Deleting Extra OUs and Users
To delete an existing OU, right-click on the OU and select Delete. When prompted for confirmation, click Yes. This should delete the OU in question unless it is protected against accidental deletion, in which case you will receive the following error message.

![OU Deletion Error](../../assets/images/thm/activedirectorybasics/05%20-%20OU%20Delete%20Error.png)

By default, OUs are protected against accidental deletion. To delete protected OUs, `Advanced Features` need to be enabled in the `View` menu.

![Enable Advanced Features](../../assets/images/thm/activedirectorybasics/06%20-%20advanced%20features.png)

Enabling Advanced Features will display additional containers and will enable us to disable accidental deletion protection. Right-click on the OU and go to the Properties. Under the `Object` tab, uncheck `Protect object from accidental deletion`.

![Protect Object From Accidental Deletion](../../assets/images/thm/activedirectorybasics/07%20-%20disable%20deletion%20protection.png)

Click Apply and OK to exit out of the Properties window. Now we should be able to right-click the OU and delete it without issue. You will be prompted to confirm that you want to delete the OU; any users, groups, or OUs under it will also be deleted.

### Delegation
Active Directory provides the ability to give specific users some control over some OUs. This process is known as **delegation** and allows us to grant users specific privileges to perform advanced tasks on OUs without needing a Domain Admin to intervene. An example of where delegation is useful is granting IT support group privileges to reset other low-level users' passwords.

To delegate control over an OU, right-click on the OU and select `Delegate Control`.

![Delegate Control](../../assets/images/thm/activedirectorybasics/08%20-%20delegate%20control.png)

This will open a new window where we will be asked the name of the user to whom we wish to delegate control to. Click Add and enter the name of the user to whom we wish to delegate control to under the `Enter the object names to select` section. It is advisable to use the `Check Names` functionality to avoid mistyping the user's name.

![Delegate Control Add User](../../assets/images/thm/activedirectorybasics/09%20-%20delegate%20add%20user.png)

![Delegate Control Select User](../../assets/images/thm/activedirectorybasics/10%20-%20delegate%20select%20user.png)

Click OK and Next. As we are attempting to delegate password reset privileges, in the next window, select the appropriate task we wish to delegate.

![Delegate Control Password Reset](../../assets/images/thm/activedirectorybasics/11%20-%20delegate%20password%20reset.png)

Click Next and then Finish to complete the delegation.

As a side note, when delegating tasks such as password reset, low-privilege user may not have the correct privileges access to the Active Directory Users and Computers window. In this case, Powershell can be utilized to complete the task. For example, `phillip` can reset the password for for the user `sophie` with the following commands:

```powershell
PS C:\Users\phillip> Set-ADAccountPassword sophie -Reset -NewPassword (Read-Host -AsSecureString -Prompt 'New Password') -Verbose

New Password: *********

VERBOSE: Performing the operation "Set-ADAccountPassword" on target "CN=Sophie,OU=Sales,OU=THM,DC=thm,DC=local".

PS C:\Users\phillip> Set-ADUser -ChangePasswordAtLogon $true -Identity sophie -Verbose

VERBOSE: Performing the operation "Set" on target "CN=Sophie,OU=Sales,OU=THM,DC=thm,DC=local".
```
## Managing Computers in Active Directory
By default, all machines that join a domain (except for the Domain Controllers) will be placed under the container called *Computers*.

While there is no golden rule on how to organize machines on a domain, an excellent starting point is segregating devices according to their use. In general, it is expected to have devices divided into at least the following three categories:

- **Workstations**: Workstations are one of the common devices within an Active Directory domain. Each user in the domain will likely be logging into a workstation. This is the device they will use to do their work or normal browsing activities. These devices should never have a privileged user signed into them.
- **Servers**: Servers are the second most common devices within an Active Directory domain. Servers are generally used to provide services to users or other servers.
- **Domain Controllers**: Domain Controllers are the third most common devices within an Active Directory domain. Domain Controllers allow you to manage the Active Directory domain. These devices are often deemed the most sensitive devices within the network as they contain hashed passwords for all user accounts within the environment.

A machine can be moved to designated OU by right-clicking on the machine and selecting Move in the context menu.

## Group Policies
The key benefit of Active Directory is the ability to deploy different policies for each OU individually. This way, we can push different configurations and security baselines to users depending on their department and function.

Windows manages such policies through **Group Policy Objects (GPO)**. GPOs are simply collection of settings that can be applied to OUs. GPOs can contain policies aimed at either users or computers, allowing us to set a baseline on specific machines and identities.

To configure GPOs, the Group Policy Management tool is used.

![GPO Search](../../assets/images/thm/activedirectorybasics/12%20-%20GPO%20Search.png)

To configure Group Policies we first need to create a GPO under `Group Policy Objects` and then link it to the GPO where we want the policies to apply. As an example, we can see there are some already existing GPOs on the following machine:

![GPO](../../assets/images/thm/activedirectorybasics/13%20-%20GPO.png)

We can see in the image above that 3 GPOs have been created. From those, the `Default Domain Policy` and `RDP Policy` are linked to the `thm.local` domain as a whole, and the `Default Domain Controllers Policy` is linked to the `Domain Controllers` OU only. It is important to note that a GPO will apply to the linked OU and any sub-OUs under it.

To edit a GPO, right-click on the GPO and select *Edit* in the context menu.

### GPO Distribution
GPOs are distributed to the network via a network share called `SYSVOL`, which is stored in the Domain Controller. All users typically have access to this share over the network to sync their GPOs periodically. The SYSVOL share points by default to `C:\Windows\SYSVOL\sysvol\` directory on each of the Domain Controllers in the network.

Once a change has been made to any GPOs, it can take up to 2 hours for computers to synchronize. A computer can be forced to sync its GPOs immediately by running the following command:

```powershell
PS C:\> gpupdate /force
```
## Authentication Methods
When using Windows domains, all credentials are stored in the Domain Controllers. Whenever a user tries to authenticate to a service suing domain credentials, the service will need to ask the Domain Controller to verify if they are correct. Two protocols can be sued for network authentication in Windows domains:

- **Kerberos**: Used by any recent version of Windows. This is the default protocol in any recent domain.
- **NetNTLM**: Legacy authentication protocol for compatibility purposes.

While NetNTLM should be considered obsolete, most networks will have both protocols enabled.

Let's look deeper at how each protocol works.

### Kerberos Authentication
Kerberos authentication is the default authentication protocol for any recent version of Windows. Users who log into a service using Kerberos will be assigned tickets. These tickets can be though of as proof of previous authentication. Users with tickets can present them to a service to demonstrate they have already authenticated into the network before and therefore enabled to use it.

Following is the basic process for Kerberos authentication:

1. The user sends their username and a timestamp encrypted using a key derived from their password to the **Key Distribution Center (KDC)**. KDC is a service usually installed on the Domain Controller which is in-charge of creating Kerberos tickets on the network.
<br><br>
The KDC will create and send back a **Ticket Granting Ticket (TGT)** which allows the user to request additional tickets to access specific services. The need for a ticket to get more tickets allows users to request service tickets without passing their credentials every time they want to connect to a service. Along with TGT, a **Session Key** is given to the user which they will need to generate the following requests.
<br><br>
The TGT is encrypted using the **krbtgt** account's password hash and therefore the user can't access its contents. The encrypted TGT includes a copy of the Sessions Key as part of its content and the KDC has no need to store the Session Key as it can recover a copy by decrypting the TGT if needed.
<br><br>
![Request TGT](../../assets/images/thm/activedirectorybasics/14%20-%20kerberos.png)

2. When a user wants to connect to a service on the network like a share, website, or database, they will use their TGT to ask the KDC for a **Ticket Granting Service (TGS)**. TGS are tickets that allow connection only to the specific service they were created for. To request TGS, the user will send their username and timestamp encrypted using the Session Key, along with the TGT and a **Service Principal Name (SPN)** which indicates the service and server name we intend to access.
<br><br>
As a result, the KDC will send us a TGS along with a **Service Session Key**, which we will need to authenticate to the service we want to access. The TGS is encrypted using a key derived form the **Service Owner Hash**. The Service Owner is the user or machine account that the service runs under. The TGS contains a copy of the Service Session Key in its encrypted contents so that the Service Owner can access it by decrypting the TGS.
<br><br>
![Request TGS](../../assets/images/thm/activedirectorybasics/15%20-%20kerberos-2.png)

3. The TGS can then be sent to the desired service to authenticate and establish a connection. The service will use its configured account's password hash to decrypt the TGS and validate the Service Session Key.
<br><br>
![Kerberos Authenticate](../../assets/images/thm/activedirectorybasics/16%20-%20kerberos-3.png)

### NetNTLM Authentication
NetNTLM works by using a challenge-response mechanism. The entire process is as follows:

![NetNTLM Authentication](../../assets/images/thm/activedirectorybasics/17%20-%20netntlm.png)

1. The client sends an authentication request to the server they want to access.
2. The server generates a random number and sends it as a challenge to the client.
3. The client combines their NTLM password hash with the challenge (and other known data) to generate a response to the challenge and sends it back to the server for verification.
4. The server forwards the challenge and the response to the Domain Controller for verification.
5. The Domain Controller uses the challenge to recalculate the response and compares it to the original response sent by the client. If they both match, the client is authenticated; otherwise, access is denied. The authentication result is sent back to the server.
6. The server forwards the authentication result ot the client.

Note that the user's password (or hash) is never transmitted through the network for security.

## Trees, Forests and Trusts
As companies grow, so do their networks. Having a single domain for a company is only feasible for small enterprises. As organizations grow, additional domains will inevitably need to be added.

### Trees
Active Directory supports integrating multiple domains so that the network can be partitioned into units that can be managed independently. If two domains share the same namespace (ie: thm.local), those domains can be joined into **Tree**.

In our example, if the `thm.local` (Domain Controller Root) was split into two subdomains for UK and US branches, we could build a tree with a root domain of `thm.local` and two subdomains called `uk.thm.local` and `us.thm.local`, each with its on Active Directory, computers, and users.

![Tree](../../assets/images/thm/activedirectorybasics/18%20-%20tree.png)

This partitioned structure gives us better control over who can access what in the domain. Group policies can also be configured independently for each domain in the tree.

A new security group needs to be introduced when talking about trees and forests. The **Enterprise Admins Group** will grant a user administrative privileges over all of an enterprise's domains. Each domain would still have its Domain Admins with administrator privileges over their single domains and the Enterprise Admins who can control everything in the enterprise.

### Forests
The domains you manage can also be configured in different namespaces. Suppose a company continues to grow and eventually acquires another company called `MHT Inc`. When both companies merge, there will be different domain trees for each company. The union of several trees with different namespaces into the same network is known as **forests**.

![Forest](../../assets/images/thm/activedirectorybasics/19%20-%20forest.png)

### Trust Relationships
A trust relationship between domains allows us to authorize a user from a different domain to access resources from our domain. The simplest trust relationship that can be established is a **one-way trust relationship**. In a one-way trust, if `Domain-AAA` trusts `Domain-BBB` then a user on BBB can be authorized to access resources on AAA.

![Trust Relationship](../../assets/images/thm/activedirectorybasics/20%20-%20trust%20relationship.png)

The direction of the one-way trust relationship is contrary to that of the access direction.

**Two-way trust relationships** can also be made to allow bidirectional authorization of users. By default, joining several domains under a tree or a forest will form a two-way trust relationship.

It is important to note that having a trust relationship between domains does not automatically grant access to all resources on other domains. Once a trust relationship is established, you have the chance to authorize users across different domains, but it is up to you what is actually authorized or not.
