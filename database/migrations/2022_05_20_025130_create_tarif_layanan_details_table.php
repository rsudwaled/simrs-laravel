<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('tarif_layanan_details', function (Blueprint $table) {
            $table->id();
            $table->string('kodetarifdetail')->unique();
            $table->string('kodetarif');
            $table->string('kelas');
            $table->string('totaltarif');
            $table->string('userid');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('tarif_layanan_details');
    }
};
