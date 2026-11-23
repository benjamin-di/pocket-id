<script lang="ts">
	import SearchableMultiSelect from '#lib/components/form/searchable-multi-select.svelte';
	import UserGroupService from '#lib/services/user-group-service.ts';
	import { debounced } from '#lib/utils/debounce-util.ts';
	import { onMount } from 'svelte';

	let {
		id = 'default-groups',
		selectedGroupIds = $bindable(),
		onChange
	}: {
		id?: string;
		selectedGroupIds: string[];
		onChange?: () => void;
	} = $props();

	const userGroupService = new UserGroupService();

	let userGroups = $state<{ value: string; label: string }[]>([]);
	let isLoading = $state(false);
	const labelCache = new Map<string, string>();
	let latestRequestId = 0;

	async function loadUserGroups(search?: string) {
		const requestId = ++latestRequestId;
		const listed = (await userGroupService.list({ search })).data.map((group) => {
			const label = group.friendlyName || group.name;
			labelCache.set(group.id, label);
			return { value: group.id, label };
		});
		if (requestId !== latestRequestId) return;

		const missingIds = selectedGroupIds.filter(
			(selectedId) => !listed.some((g) => g.value === selectedId) && !labelCache.has(selectedId)
		);
		if (missingIds.length > 0) {
			const fetched = await Promise.allSettled(
				missingIds.map((missingId) => userGroupService.get(missingId))
			);
			if (requestId !== latestRequestId) return;
			for (const result of fetched) {
				if (result.status === 'fulfilled') {
					labelCache.set(result.value.id, result.value.friendlyName || result.value.name);
				}
			}
		}

		const merged = [...listed];
		for (const selectedId of selectedGroupIds) {
			if (!merged.some((g) => g.value === selectedId)) {
				const cachedLabel = labelCache.get(selectedId);
				if (cachedLabel) {
					merged.push({ value: selectedId, label: cachedLabel });
				}
			}
		}
		userGroups = merged;
	}

	const onUserGroupSearch = debounced(
		async (search: string) => await loadUserGroups(search),
		300,
		(loading) => (isLoading = loading)
	);

	onMount(() => {
		loadUserGroups().catch(() => {
			/* Ignore initial lookup failure; user can retry via search */
		});
	});
</script>

<SearchableMultiSelect
	{id}
	items={userGroups}
	oninput={(e) => onUserGroupSearch(e.currentTarget.value)}
	selectedItems={selectedGroupIds}
	onSelect={(selected) => {
		selectedGroupIds = selected;
		onChange?.();
	}}
	{isLoading}
	disableInternalSearch
/>
