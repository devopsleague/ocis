package design

import (
	. "goa.design/model/dsl"
	"goa.design/model/expr"
)

var _ = Design(func() {
	Enterprise("Enterprise")
	Version("v0.0")

	Person("External User", "A person outside the enterprise", func() {
		Uses("oCIS", "manages files, folders and shares with")

		Tag("Person")
	})
	var EndUser = Person("End User", "A person part of an enterprise", func() {
		External()

		Uses("oCIS", "manages files, folders and shares with", Synchronous, func() {
			Tag("Relationship", "Synchronous")
		})
		Uses("oCIS/Android App", "manages files, folders and shares with", Synchronous, func() {
			Tag("Relationship", "Synchronous")
		})
		Uses("oCIS/iOS App", "manages files, folders and shares with", Synchronous, func() {
			Tag("Relationship", "Synchronous")
		})
		Uses("oCIS/Web Single-Page Application", "manages files, folders and shares with", "HTTPS", Synchronous, func() {
			Tag("Relationship", "Synchronous")
		})
		Uses("oCIS/Desktop client", "syncs and manages files, folders and shares with", Synchronous, func() {
			Tag("Relationship", "Synchronous")
		})
		Uses("Identity Management", "authenticates using", Synchronous, func() {
			Tag("Relationship", "Synchronous")
		})
		Tag("Person")
	})
	/*var Admin =*/ Person("Admin", "Manages the EFSS Platform", func() {
		Uses("oCIS", "provisions storage")
		Uses("Identity Management", "authenticates using")

		Tag("Person")
	})

	var IdentityManagementSystem = SoftwareSystem("Identity Management", "Manages and authenticates users", func() {

		External()

		Tag("Software System", "Existing System")
	})
	// TODO is actually a component?
	var StorageSystem = SoftwareSystem("Storage System", "persists all data", func() {

		External()

		Tag("Software System", "Existing System")
	})

	var (
		// Forward declaration so variables can be used to define views.
		OcisProxy   *expr.Container
		OcisStorage *expr.Container
		OcisWeb     *expr.Container
		// clients
		WebSinglePageApp *expr.Container
		AndroidApp       *expr.Container
		IOSApp           *expr.Container
		DesktopClient    *expr.Container
	)

	var oCISSystem = SoftwareSystem("oCIS", "Enterprise File Sync and Share", func() {

		Uses("Identity Management", "Authenticates and identifies users with", "OpenID Connect, LDAP", Synchronous)
		Uses("Storage System", "Manages access to", "POSIX, SMB, S3", Synchronous)

		Tag("Software System")

		// TODO hide this it only clutters the container diagram, similar to a message bus
		// TODO all clients "Makes API calls to" ... the proxy. better to show actual calls to the graph, frontend ...
		// TODO indicate that there is an API gateway that can route based on user ... where? in the label of a relationship?
		OcisProxy = Container("ocis proxy", "routes requests based on the logged in user", "golang, go-micro", func() {
			Uses(IdentityManagementSystem, "Makes API calls to", "OpenId Connect", Synchronous, func() {
				Tag("Relationship", "Synchronous")
			})
			Uses(OcisStorage, "forwards API calls to", "HTTP", Synchronous, func() {
				Tag("Relationship", "Synchronous")
			})
			Tag("Element", "Container")
		})

		OcisStorage = Container("ocis storage", "an opinionated reva configuration", "golang, reva", func() {
			Component("frontend", "runs all web facing services", "golang, reva", func() {
				Uses("gateway", "Uses", "CS3/GRPC", Synchronous, func() {
					Tag("Relationship", "Synchronous")
				})
				Tag("Element", "Component")
			})

			// TODO leave out the gateway?
			Component("gateway", "api gateway for reva", "reva", func() {
				Uses("Identity Management", "Uses", Synchronous, func() {
					Tag("Relationship", "Synchronous")
				})
				Tag("Element", "Component")
			})
			Component("storage provider", "implements access to a storage system", "reva", func() {
				Uses(StorageSystem, "reads and writes to", Synchronous, func() {
					Tag("Relationship", "Synchronous")
				})
				Tag("Element", "Component")
			})
			Uses(StorageSystem, "reads and writes from", "POSIX, SMB, S3", Synchronous, func() {
				Tag("Relationship", "Synchronous")
			})
		})

		AndroidApp = Container("Android App", "Provides a limited subset of the Internet banking functionality to customers via their mobile device.", "kotlin", func() {
			Uses(OcisProxy, "Makes API calls to", "WebDAV, OCS", Synchronous, func() {
				Tag("Relationship", "Synchronous")
			})
			Uses("ocis storage/frontend", "Makes API calls to", "JSON/HTTPS", Synchronous, func() {
				Tag("Relationship", "Synchronous")
			})
			Tag("Element", "Container", "Mobile App")
		})

		IOSApp = Container("iOS App", "Provides a limited subset of the Internet banking functionality to customers via their mobile device.", "xcode", func() {
			Uses(OcisProxy, "Makes API calls to", "WebDAV, OCS", Synchronous, func() {
				Tag("Relationship", "Synchronous")
			})
			Uses("ocis storage/frontend", "Makes API calls to", "JSON/HTTPS", Synchronous, func() {
				Tag("Relationship", "Synchronous")
			})
			Tag("Element", "Container", "Mobile App")
		})

		WebSinglePageApp = Container("Web Single-Page Application", "Provides all of the Internet banking functionality to customers via their web browser.", "JavaScript and Angular", func() {
			Uses("ocis storage/frontend", "Submits credentials to", "JSON/HTTPS", Synchronous, func() {
				Tag("Relationship", "Synchronous")
			})
			Uses(OcisProxy, "Makes API calls to", "WebDAV, OCS", Synchronous, func() {
				Tag("Relationship", "Synchronous")
			})
			Tag("Element", "Container", "Web Browser")
		})

		OcisWeb = Container("ocis web", "Delivers the static content and the ocis web single page application.", "golang and vue", func() {
			Uses(WebSinglePageApp, "Delivers to the users web browser", Synchronous, func() {
				Tag("Relationship", "Synchronous")
			})
			Tag("Element", "Container")
		})

		DesktopClient = Container("Desktop client", "syncs files with the users computer", "C++", func() {
			Uses(OcisProxy, "syncs with", "WebDAV, OCS, openGraphAPI", Synchronous, func() {
				Tag("Relationship", "Synchronous")
			})
			Tag("Element", "Container", "Desktop Client")
		})
	})

	var (
		// Forward declarations so variables can be used in deployment views.
		DataCenter         *expr.DeploymentNode
		BigBankAPI         *expr.DeploymentNode
		LiveAPIApp         *expr.DeploymentNode
		LiveAPIAppInstance *expr.ContainerInstance
		BigBankWeb         *expr.DeploymentNode
		LiveWebApp         *expr.DeploymentNode
		LiveWebAppInstance *expr.ContainerInstance
		CustomerComputer   *expr.DeploymentNode
		LiveWebBrowser     *expr.DeploymentNode
		CustomerSPA        *expr.ContainerInstance
		CustomerMobile     *expr.DeploymentNode
		CustomerAndroidApp *expr.ContainerInstance
	)

	DeploymentEnvironment("Live", func() {

		DataCenter = DeploymentNode("Enterprise", "", "Enterprise data center", func() {
			Tag("Element", "Deployment Node")

			BigBankAPI = DeploymentNode("bigbank-api***", "A web server residing in the web server farm, accessed via F5 BIG-IP LTMs.", "Ubuntu 16.04 LTS", func() {
				Tag("Element", "Deployment Node")
				Instances(8)
				Prop("Location", "London and Reading")

				LiveAPIApp = DeploymentNode("Apache Tomcat", "An open source Java EE web server.", "Apache Tomcat 8.x", func() {
					Tag("Element", "Deployment Node")
					Prop("Java Version", "8")
					Prop("Xms", "1024M")
					Prop("Xmx", "512M")

					LiveAPIAppInstance = ContainerInstance(OcisProxy, func() {
						Tag("Container Instance")
						InstanceID(2)
					})
				})
			})

			BigBankWeb = DeploymentNode("bigbank-web***", "A web server residing in the web server farm, accessed via F5 BIG-IP LTMs.", "Ubuntu 16.04 LTS", func() {
				Tag("Element", "Deployment Node")
				Instances(4)
				Prop("Location", "London and Reading")

				LiveWebApp = DeploymentNode("Apache Tomcat", "An open source Java EE web server.", "Apache Tomcat 8.x", func() {
					Tag("Element", "Deployment Node")
					Prop("Java Version", "8")
					Prop("Xms", "1024M")
					Prop("Xmx", "512M")

					LiveWebAppInstance = ContainerInstance(OcisWeb, func() {
						Tag("Container Instance")
						InstanceID(2)
					})
				})
			})
		})

		CustomerComputer = DeploymentNode("Customer's computer", "", "Microsoft Windows or Apple macOS", func() {
			Tag("Element", "Deployment Node")

			LiveWebBrowser = DeploymentNode("Web Browser", "", "Chrome, Firefox, Safari or Edge", func() {
				Tag("Element", "Deployment Node")

				CustomerSPA = ContainerInstance(WebSinglePageApp, func() {
					Tag("Container Instance")
				})
			})
		})

		CustomerMobile = DeploymentNode("Customer's mobile device", "", "Apple iOS or Android", func() {
			Tag("Element", "Deployment Node")

			CustomerAndroidApp = ContainerInstance(AndroidApp, func() {
				Tag("Container Instance")
			})
		})
	})

	Views(func() {
		SystemContextView(oCISSystem, "oCIS Context", "C4 System Context diagram for oCIS", func() {
			EnterpriseBoundaryVisible()
			AddAll()
			AutoLayout(RankTopBottom, func() {

				// Separation between ranks in pixels, defaults to 300.
				RankSeparation(300)

				// Separation between nodes in the same rank in pixels, defaults to 600.
				NodeSeparation(600)

				// Separation between edges in pixels, defaults to 200.
				EdgeSeparation(200)

				// Create vertices during automatic layout, false by default.
				RenderVertices()
			})
		})

		ContainerView(oCISSystem, "oCIS Containers", "The container diagram for the oCIS System.", func() {
			PaperSize(SizeA5Landscape)

			Add(EndUser, func() {
				Coord(1056, 24)
			})
			Add(IdentityManagementSystem, func() {
				Coord(2012, 1214)
			})
			Add(StorageSystem, func() {
				Coord(2012, 1214)
			})
			Add(WebSinglePageApp, func() {
				Coord(780, 664)
			})
			Add(AndroidApp, func() {
				Coord(1283, 664)
			})
			Add(IOSApp, func() {
				Coord(1283, 664)
			})
			Add(OcisWeb, func() {
				Coord(37, 664)
			})
			Add(DesktopClient, func() {
				Coord(1283, 664)
			})
			Add(OcisProxy, func() {
				Coord(1031, 1214)
			})
			Add(OcisStorage, func() {
				Coord(1031, 1214)
			})

			// Make software system boundaries visible for "external" containers
			// (those outside the software system in scope).
			SystemBoundariesVisible()

			AutoLayout(RankTopBottom)
		})

		DeploymentView(oCISSystem, "Live", "LiveDeployment", "An example live deployment scenario for the oCIS System.", func() {
			PaperSize(SizeA5Landscape)
			AutoLayout(RankLeftRight)

			Add(LiveWebBrowser)
			Add(CustomerComputer)
			Add(CustomerMobile)
			Add(DataCenter)
			Add(BigBankWeb)
			Add(LiveWebApp)
			Add(BigBankAPI)
			Add(LiveAPIApp)

			AnimationStep(LiveWebBrowser, CustomerSPA, CustomerComputer)
			AnimationStep(CustomerMobile, CustomerAndroidApp)
			AnimationStep(DataCenter, BigBankWeb, LiveWebApp, LiveWebAppInstance, BigBankAPI, LiveAPIApp, LiveAPIAppInstance)
		})
		Styles(func() {
			ElementStyle("Software System", func() {
				Background("#1168bd")
				Color("#ffffff")
			})
			ElementStyle("Container", func() {
				Background("#438dd5")
				Color("#ffffff")
			})
			ElementStyle("Component", func() {
				Background("#85bbf0")
				Color("#000000")
			})
			ElementStyle("Person", func() {
				Background("#08427b")
				Color("#ffffff")
				FontSize(22)
				Shape(ShapePerson)
			})
			ElementStyle("Existing System", func() {
				Background("#999999")
				Color("#ffffff")
			})
			ElementStyle("Web Browser", func() {
				Shape(ShapeWebBrowser)
			})
			ElementStyle("Mobile App", func() {
				Shape(ShapeMobileDeviceLandscape)
			})
			ElementStyle("Desktop Client", func() {
				Shape(ShapeRoundedBox)
			})
			ElementStyle("Database", func() {
				Shape(ShapeCylinder)
			})
			ElementStyle("Failover", func() {
				Opacity(25)
			})
			RelationshipStyle("Failover", func() {
				Opacity(25)
			})
		})
	})

})
