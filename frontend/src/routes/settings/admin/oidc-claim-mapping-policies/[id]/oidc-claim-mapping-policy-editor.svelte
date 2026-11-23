<script lang="ts">
	import FormInput from '#lib/components/form/form-input.svelte';
	import SwitchWithLabel from '#lib/components/form/switch-with-label.svelte';
	import Button from '#lib/components/ui/button/button.svelte';
	import * as Card from '#lib/components/ui/card/index.ts';
	import * as Tabs from '#lib/components/ui/tabs/index.ts';
	import { m } from '#lib/paraglide/messages.js';
	import OidcClaimMappingPolicyService from '#lib/services/oidc-claim-mapping-policy-service.ts';
	import {
		builtInClaimMappingPolicyId,
		type OidcClaimMappingPolicy
	} from '#lib/types/oidc-claim-mapping-policy.type.ts';
	import { createForm } from '#lib/utils/form-util.ts';
	import { trackFormChanges } from '#lib/utils/unsaved-changes-util.svelte.ts';
	import { LucideChevronLeft } from '@lucide/svelte';
	import { toast } from 'svelte-sonner';
	import { z } from 'zod/v4';
	import OidcClientPreviewModal from '../../oidc-clients/oidc-client-preview-modal.svelte';
	import { backNavigate } from '../../users/navigate-back-util';
	import OidcClaimMappingPolicyClientsTab from './oidc-claim-mapping-policy-clients-tab.svelte';
	import OidcClaimMappingsCard from './oidc-claim-mappings-card.svelte';

	let { initialPolicy }: { initialPolicy: OidcClaimMappingPolicy } = $props();

	let policy = $state<OidcClaimMappingPolicy>(initialPolicy);
	let activeTab = $state('general');
	let clientsTab = $state<OidcClaimMappingPolicyClientsTab>();
	let mappingsCard = $state<OidcClaimMappingsCard>();
	let showPreview = $state(false);

	const readOnly = $derived(policy.id === builtInClaimMappingPolicyId);

	const claimMappingPolicyService = new OidcClaimMappingPolicyService();
	const backNavigation = backNavigate('/settings/admin/oidc-claim-mapping-policies');

	const policySchema = z.object({
		name: z.string().min(1),
		isDefault: z.boolean(),
		claimMappings: z.array(
			z.object({
				claimName: z.string().min(1),
				sourceType: z.enum(['user_field', 'custom_claim', 'static']),
				sourceValue: z.string().min(1),
				scope: z.array(
					z
						.string()
						.min(1)
						.max(128)
						.regex(/^[\x21\x23-\x5B\x5D-\x7E]+$/)
				),
				accessToken: z.boolean(),
				idToken: z.boolean(),
				userInfo: z.boolean()
			})
		)
	});

	const formStore = createForm(policySchema, {
		name: policy.name,
		isDefault: policy.isDefault,
		claimMappings: policy.claimMappings ?? []
	});
	const { inputs } = formStore;

	async function updatePolicy(data: z.infer<typeof policySchema>) {
		if (!policy.id) return;
		policy = await claimMappingPolicyService.updateClaimMappingPolicy(policy.id, {
			name: data.name,
			isDefault: data.isDefault,
			claimMappings: data.claimMappings
		});
		toast.success(m.claim_mapping_policy_updated_successfully());
	}

	trackFormChanges(() => formStore, updatePolicy, {
		discard: () => {
			mappingsCard?.refresh();
		}
	});

	let clientId = $state('');
	let clientName = $state('');
	let isLoadingPreviewClient = $state(false);
	let previewLookupError = $state(false);
	let previewRequestId = 0;

	async function fetchClientForPreview() {
		if (!policy.id) return;
		const reqId = ++previewRequestId;
		clientId = '';
		clientName = '';
		previewLookupError = false;
		isLoadingPreviewClient = true;

		try {
			const assigned = await claimMappingPolicyService.listClients(policy.id, {
				pagination: { page: 1, limit: 1 }
			});
			if (reqId !== previewRequestId) return;
			if (assigned.data[0]) {
				clientId = assigned.data[0].id;
				clientName = assigned.data[0].name;
				return;
			}

			if (policy.isDefault) {
				// For the default policy, only select a client without an explicit policy assignment
				let page = 1;
				while (true) {
					const assignable = await claimMappingPolicyService.listAssignableClients(policy.id, {
						pagination: { page, limit: 100 }
					});
					if (reqId !== previewRequestId) return;
					const inheriting = assignable.data.find((c) => !c.claimMappingPolicyId);
					if (inheriting) {
						clientId = inheriting.id;
						clientName = inheriting.name;
						return;
					}
					if (page >= (assignable.pagination?.totalPages ?? 1) || assignable.data.length === 0) {
						break;
					}
					page++;
				}
			}
		} catch {
			if (reqId === previewRequestId) {
				previewLookupError = true;
			}
		} finally {
			if (reqId === previewRequestId) {
				isLoadingPreviewClient = false;
			}
		}
	}

	$effect(() => {
		if (activeTab === 'preview' && policy.id) {
			fetchClientForPreview();
		}
	});
</script>

<svelte:head>
	<title>{m.edit_claim_mapping_policy()}</title>
</svelte:head>

<div class="flex items-center justify-between">
	<button class="text-muted-foreground flex text-sm" onclick={() => backNavigation.go()}
		><LucideChevronLeft class="size-5" /> {m.back()}</button
	>
</div>

<Tabs.Root bind:value={activeTab} useHash class="gap-4">
	<div class="overflow-x-auto pb-1">
		<Tabs.List variant="line" class="min-w-max">
			<Tabs.Trigger value="general">{m.general()}</Tabs.Trigger>
			<Tabs.Trigger value="clients">{m.oidc_clients()}</Tabs.Trigger>
			<Tabs.Trigger value="preview">{m.oidc_data_preview()}</Tabs.Trigger>
		</Tabs.List>
	</div>

	<Tabs.Content value="general" class="flex flex-col gap-4">
		<Card.Root>
			<Card.Header>
				<Card.Title>{m.general()}</Card.Title>
			</Card.Header>

			<Card.Content>
				<div class="grid grid-cols-1 gap-x-3 gap-y-7 sm:flex-row md:grid-cols-2">
					<FormInput
						label={m.name()}
						class="w-full"
						bind:input={$inputs.name}
						placeholder={m.enter_policy_name()}
						disabled={readOnly}
					/>
					<div>
						<SwitchWithLabel
							id="isDefault"
							label={m.set_as_default()}
							description={m.set_as_default_description()}
							bind:checked={$inputs.isDefault.value}
							disabled={readOnly && policy.isDefault}
						/>
					</div>
				</div>
			</Card.Content>
		</Card.Root>

		<OidcClaimMappingsCard
			bind:this={mappingsCard}
			policyId={policy.id!}
			bind:claimMappings={$inputs.claimMappings.value}
			{readOnly}
		/>
	</Tabs.Content>

	<Tabs.Content value="clients" class="flex flex-col gap-4">
		<Card.Root>
			<Card.Header>
				<div class="flex flex-wrap items-center justify-between gap-4 md:flex-nowrap">
					<div>
						<Card.Title>{m.oidc_clients()}</Card.Title>
						<Card.Description>{m.claim_mapping_policy_clients_description()}</Card.Description>
					</div>
					<Button class="w-full md:w-auto" onclick={() => clientsTab?.openPicker()}>
						{m.assign_client()}
					</Button>
				</div>
			</Card.Header>
			<Card.Content>
				<OidcClaimMappingPolicyClientsTab bind:this={clientsTab} policyId={policy.id!} />
			</Card.Content>
		</Card.Root>
	</Tabs.Content>

	<Tabs.Content value="preview" class="flex flex-col gap-4">
		<Card.Root>
			<Card.Header>
				<div class="flex flex-col items-start justify-between gap-3 sm:flex-row sm:items-center">
					<div>
						<Card.Title>
							{m.oidc_data_preview()}
						</Card.Title>
						<Card.Description>
							{m.preview_the_oidc_data_that_would_be_sent_for_different_users()}
							{#if isLoadingPreviewClient}
								<p class="text-muted-foreground mt-3 text-sm">Loading...</p>
							{:else if previewLookupError}
								<p class="text-destructive mt-3 text-sm">
									Failed to load an eligible client for preview.
								</p>
							{:else if clientId === ''}
								<p class="text-muted-foreground mt-3 text-sm">
									{m.claim_mapping_policy_preview_disabled()}
								</p>
							{:else if clientName}
								<p class="text-muted-foreground mt-3 text-sm">
									Previewing using client: <span class="font-medium">{clientName}</span>
								</p>
							{/if}
						</Card.Description>
					</div>

					<Button
						variant="outline"
						onclick={() => (showPreview = true)}
						disabled={isLoadingPreviewClient || clientId === ''}
					>
						{m.show()}
					</Button>
				</div>
			</Card.Header>
		</Card.Root>
	</Tabs.Content>
</Tabs.Root>

<OidcClientPreviewModal bind:open={showPreview} {clientId} />
