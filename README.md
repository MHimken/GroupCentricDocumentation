# Group Centric Documentation

In this 'small' project, I was fed up with the fact that there's no easy way to visualize what's assigned to a specific group. The main goal here is to make mistakes, that are often made with assignments, more visible. Planning and monitoring are more manageable on a human readable level. It also helps to document current assignments for later comparison. This does not import/export any data, it's a visualization tool.

This is the very first version of this solution and will be expanded over time. More information can be found here <https://manima.de/2023/10/group-centric-documentation-for-intune-part-1>

## Output formats

* JSON
* In development: Mermaid (Try out now by using [Mermaid](https://mermaid.live/) and the provided [Example File](Mermaid-Mindmap-Example.md))
* Eventually: Powerpoint

## Setup

 You need a way to connect to the Graph API. I used a custom enterprise application with a self-signed certificate to connect, so parameters for that are available if required. I also involved the [Microsoft.Graph module](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation?view=graph-powershell-1.0). The minimum scope for this script to work are:

* DeviceManagementApps.Read.All
* DeviceManagementConfiguration.Read.All
* DeviceManagementServiceConfig.Read.All
* Group.Read.All

It is possible to connect to Graph first using `Connect-MgGraph -Scopes DeviceManagementApps.Read.All,DeviceManagementConfiguration.Read.All,DeviceManagementServiceConfig.Read.All,Group.Read.All`.

## Considerations

* This script was written to be as fast as possible. In a medium sized environment, it's not uncommon for it to run in 30-60 seconds. Larger environments should expect longer.
* This script currently lacks any error handling. This includes the famous `429 Too Many Requests` error. General Graph throttling limits can be [found here](https://learn.microsoft.com/en-us/graph/throttling-limits). However, even with extensive testing, I haven't been able to hit any of these limits (especially using only `GET` this seems unlikely unless you have a _lot_ of groups).
* I strongly recommend that you build your own application using certificates instead of secrets. **Never use secrets in your scripts!**

## Closing words

This project has taken me more time than anything I've ever written (without a customer paying for it). I write these solutions in my spare time because I enjoy it! If you find any kind of problem, bug or have a feature request, please don't hesitate to contact me. I'd appreciate bug reports on GitHub, contact me using the methods provided on my blog (see the top of this readme), or via the WinAdmins Discord <https://winadmins.io/>.
