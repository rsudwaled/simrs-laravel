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
        Schema::create('seps', function (Blueprint $table) {
            $table->id();
            $table->string('noSep')->unique()->index();
            $table->string('noRujukan');
            $table->string('noSurat');
            // detail sep
            $table->date('tglSep');
            $table->string('jnsPelayanan')->nullable();
            $table->string('kelasRawat')->nullable();
            $table->string('diagnosa')->nullable();
            $table->string('poli')->nullable();
            $table->string('poliEksekutif')->nullable();
            $table->string('catatan')->nullable();
            $table->string('kdDPJP')->nullable();
            // peserta
            $table->string('noKartu')->nullable();
            $table->string('noMr')->nullable();
            $table->string('nama')->nullable();
            $table->string('noTelp')->nullable();
            // kecelakaan
            $table->string('kdStatusKecelakaan')->nullable();
            $table->string('cob')->nullable();
            $table->string('katarak')->nullable();
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
        Schema::dropIfExists('seps');
    }
};
