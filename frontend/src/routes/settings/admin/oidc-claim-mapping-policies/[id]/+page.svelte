<script lang="ts">
	import OidcClaimMappingPolicyEditor from './oidc-claim-mapping-policy-editor.svelte';

	let { data } = $props();
</script>

{#key data.policy.id}
	<OidcClaimMappingPolicyEditor initialPolicy={data.policy} />
{/key}
