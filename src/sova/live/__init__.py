# SPDX-License-Identifier: Apache-2.0
"""Authorization-gated live assessment workflows."""

from sova.live.adaptive_campaign import (
    AdaptiveBrowserCampaignArtifacts,
    AdaptiveBrowserPolicy,
    adaptive_browser_policy_from_mapping,
    run_adaptive_agent_browser_campaign,
)
from sova.live.agent_campaign import (
    AgentBrowserCampaignArtifacts,
    AgentCampaignEventObserver,
    run_agent_browser_campaign,
)
from sova.live.browser import (
    BrowserEventObserver,
    LiveBrowserArtifacts,
    build_owned_web_capsule,
    owned_web_target,
    run_live_browser_assessment,
    run_owned_web_vertical_slice,
)
from sova.live.campaign import (
    BrowserCampaign,
    BrowserCampaignArtifacts,
    CampaignEventObserver,
    browser_campaign_from_mapping,
    owned_web_campaign,
    run_browser_campaign,
    run_owned_web_campaign,
)
from sova.live.control import (
    ControlFetchResult,
    UrllibControlFetcher,
    WebsiteControlChallenge,
    challenge_from_mapping,
    collect_website_control_proof,
    control_proof_from_mapping,
    create_website_control_challenge,
)
from sova.live.fixture_web import OwnedWebFixture
from sova.live.persistent_session import (
    BrowserHandoffPrompt,
    BrowserSessionHandoffArtifacts,
    PersistentSessionArtifacts,
    run_browser_profile_handoff,
    run_owned_persistent_session_restart_probe,
)
from sova.live.software import (
    LiveSoftwareArtifacts,
    SoftwareApprovalPrompt,
    SoftwareEventObserver,
    build_owned_software_capsule,
    run_live_software_assessment,
    run_owned_software_vertical_slice,
)

__all__ = [
    "AdaptiveBrowserCampaignArtifacts",
    "AdaptiveBrowserPolicy",
    "AgentBrowserCampaignArtifacts",
    "AgentCampaignEventObserver",
    "BrowserCampaign",
    "BrowserCampaignArtifacts",
    "BrowserEventObserver",
    "BrowserHandoffPrompt",
    "BrowserSessionHandoffArtifacts",
    "CampaignEventObserver",
    "ControlFetchResult",
    "LiveBrowserArtifacts",
    "LiveSoftwareArtifacts",
    "OwnedWebFixture",
    "PersistentSessionArtifacts",
    "SoftwareApprovalPrompt",
    "SoftwareEventObserver",
    "UrllibControlFetcher",
    "WebsiteControlChallenge",
    "adaptive_browser_policy_from_mapping",
    "browser_campaign_from_mapping",
    "build_owned_software_capsule",
    "build_owned_web_capsule",
    "challenge_from_mapping",
    "collect_website_control_proof",
    "control_proof_from_mapping",
    "create_website_control_challenge",
    "owned_web_campaign",
    "owned_web_target",
    "run_adaptive_agent_browser_campaign",
    "run_agent_browser_campaign",
    "run_browser_campaign",
    "run_browser_profile_handoff",
    "run_live_browser_assessment",
    "run_live_software_assessment",
    "run_owned_persistent_session_restart_probe",
    "run_owned_software_vertical_slice",
    "run_owned_web_campaign",
    "run_owned_web_vertical_slice",
]
