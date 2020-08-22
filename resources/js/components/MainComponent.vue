<template>
    <div style="--top-bar-background:#00848e; --top-bar-background-lighter:#1d9ba4; --top-bar-color:#f9fafb; --p-frame-offset:0px;">
        <div class="Polaris-Card">
            <div class="Polaris-Card__Header">
                <h2 class="Polaris-Heading">Online store dashboard</h2>
            </div>
            <div class="Polaris-Card__Section">
                <p>View a summary of your online store’s performance.</p>
            </div>
        </div>
    </div>
</template>

<script>
    export default {
        mounted() {
            console.log('Component mounted.',this.$store.getters.getCount)
        }
    }
</script>
