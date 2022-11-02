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
        Schema::create('jadwal_dokters', function (Blueprint $table) {
            $table->id();
            $table->string('kodepoli');
            $table->string('namapoli');
            $table->string('kodesubspesialis');
            $table->string('namasubspesialis');
            $table->string('namadokter');
            $table->string('kodedokter');
            $table->string('hari');
            $table->string('namahari');
            $table->string('jadwal');
            $table->string('libur');
            $table->string('kapasitaspasien');
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
        Schema::dropIfExists('jadwal_dokters');
    }
};
